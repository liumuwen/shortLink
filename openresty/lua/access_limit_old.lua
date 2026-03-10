-- access_limit.lua
-- 限流方案：Redis 滑动窗口（Sliding Window）
-- 原理：用 Redis Sorted Set，score = 请求时间戳(ms)，
--       每次请求先清除窗口外的旧记录，再统计当前窗口内请求数，
--       超限则拒绝，否则写入当前时间戳并放行。

local redis = require "resty.redis"

-- ================= 配置区 =================
local REDIS_HOST     = "192.168.150.101"
local REDIS_PORT     = 6379
local REDIS_PASSWORD = "123456"

local BLACK_LIST_TTL = 600   -- 封禁时长（秒）

-- IP 滑动窗口配置
local IP_WINDOW_MS   = 1000  -- 窗口大小：1000 ms（1 秒）
local IP_MAX_REQ     = 50    -- 窗口内最大请求数

-- Token 滑动窗口配置
local TOKEN_WINDOW_MS = 1000 -- 窗口大小：1000 ms（1 秒）
local TOKEN_MAX_REQ  = 5     -- 窗口内最大请求数

-- ================= 工具函数 =================

local function get_client_ip()
    local headers = ngx.req.get_headers()
    local ip = headers["X-Real-IP"]
            or headers["X-Forwarded-For"]
            or ngx.var.remote_addr
            or "0.0.0.0"
    -- X-Forwarded-For 可能是逗号分隔列表，取第一个
    ip = ip:match("^[^,]+") or ip
    return ip
end

local function get_token()
    local headers = ngx.req.get_headers()
    return headers["Authorization"]
end

local function get_redis()
    local red = redis:new()
    red:set_timeout(1000)
    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        ngx.log(ngx.ERR, "[Redis] 连接失败: ", err)
        return nil
    end
    if REDIS_PASSWORD and REDIS_PASSWORD ~= "" then
        local res, err = red:auth(REDIS_PASSWORD)
        if not res then
            ngx.log(ngx.ERR, "[Redis] 认证失败: ", err)
            return nil
        end
    end
    return red
end

-- ================= 滑动窗口限流核心（Lua 脚本原子操作）=================
--
-- 使用 Redis EVAL 保证 ZREMRANGEBYSCORE / ZCARD / ZADD / EXPIRE 原子执行，
-- 防止并发竞态条件。
--
-- KEYS[1]   : Redis key（如 "sw:ip:1.2.3.4"）
-- ARGV[1]   : 当前时间戳 (ms)
-- ARGV[2]   : 窗口起始时间戳 (ms)，即 now - window_ms
-- ARGV[3]   : 最大请求数
-- ARGV[4]   : key 过期时间 (ms)，建议设为 window_ms 的 2 倍
--
-- 返回值：
--   1  → 允许通过
--   0  → 超出限制，拒绝

local SLIDING_WINDOW_SCRIPT = [[
local key        = KEYS[1]
local now        = tonumber(ARGV[1])
local window_start = tonumber(ARGV[2])
local max_req    = tonumber(ARGV[3])
local expire_ms  = tonumber(ARGV[4])

-- 1. 删除窗口之前的过期记录
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- 2. 统计当前窗口内的请求数
local count = redis.call('ZCARD', key)

if count >= max_req then
    -- 超限，不写入，直接返回 0
    return 0
end

-- 3. 写入当前请求（score=时间戳ms，member=时间戳ms+随机数防重复）
local member = now .. '-' .. redis.call('INCR', key .. ':seq')
redis.call('ZADD', key, now, member)

-- 4. 设置 key 过期时间（毫秒），避免 key 永久堆积
redis.call('PEXPIRE', key, expire_ms)

return 1
]]

---@param red table  Redis 连接对象
---@param key string  限流 key
---@param window_ms number 窗口毫秒数
---@param max_req number  窗口内最大请求数
---@return boolean allowed, string|nil err
local function sliding_window_check(red, key, window_ms, max_req)
    local now          = ngx.now() * 1000               -- 当前时间 ms（含毫秒）
    local window_start = now - window_ms                -- 窗口起始时间
    local expire_ms    = window_ms * 2                  -- key 过期时间取窗口的 2 倍

    local result, err = red:eval(
            SLIDING_WINDOW_SCRIPT,
            1,                  -- key 数量
            key,                -- KEYS[1]
            now,                -- ARGV[1]
            window_start,       -- ARGV[2]
            max_req,            -- ARGV[3]
            expire_ms           -- ARGV[4]
    )

    if err then
        return nil, "eval 失败: " .. err
    end

    return result == 1, nil
end

-- ================= 核心逻辑 =================

local client_ip = get_client_ip()
local token     = get_token()
local red       = get_redis()

-- ---- 1. Redis 不可用时的降级策略（直接放行，保证可用性）----
if not red then
    ngx.log(ngx.WARN, "[限流] Redis 不可用，降级放行，IP: ", client_ip)
    return
end

-- ---- 2. 黑名单检查 ----
local is_black, err = red:get("blacklist:ip:" .. client_ip)
if is_black == "1" then
    ngx.log(ngx.WARN, "[限流] 黑名单 IP 拦截: ", client_ip)
    red:set_keepalive(10000, 100)
    return ngx.exit(403)
end

-- ---- 3. 白名单检查 ----
local is_white, err = red:get("whitelist:ip:" .. client_ip)
if is_white == "1" then
    red:set_keepalive(10000, 100)
    return
end

-- ---- 4. 封禁函数 ----
local function ban_ip(ip)
    local ok, err = red:setex("blacklist:ip:" .. ip, BLACK_LIST_TTL, "1")
    if not ok then
        ngx.log(ngx.ERR, "[限流] 写入黑名单失败: ", err)
    end
    ngx.log(ngx.WARN, "[限流] IP 触发滑动窗口上限，封禁 ", BLACK_LIST_TTL, " 秒: ", ip)
end

-- ---- 5. Token 滑动窗口限流 ----
if token then
    -- 对 Authorization 头做简单哈希，避免 key 过长（Redis key 建议 < 512 bytes）
    local token_key = "sw:token:" .. ngx.md5(token)

    local allowed, err = sliding_window_check(
            red, token_key, TOKEN_WINDOW_MS, TOKEN_MAX_REQ
    )

    if err then
        ngx.log(ngx.ERR, "[限流] Token 滑动窗口检查失败: ", err)
        red:set_keepalive(10000, 100)
        return ngx.exit(500)
    end

    if not allowed then
        ngx.log(ngx.WARN, "[限流] Token 超出限流阈值，IP: ", client_ip)
        ban_ip(client_ip)
        red:set_keepalive(10000, 100)
        return ngx.exit(429)
    end
end

-- ---- 6. IP 滑动窗口限流 ----
local ip_key = "sw:ip:" .. client_ip

local allowed, err = sliding_window_check(
        red, ip_key, IP_WINDOW_MS, IP_MAX_REQ
)

if err then
    ngx.log(ngx.ERR, "[限流] IP 滑动窗口检查失败: ", err)
    red:set_keepalive(10000, 100)
    return ngx.exit(500)
end

if not allowed then
    ban_ip(client_ip)
    red:set_keepalive(10000, 100)
    return ngx.exit(429)
end

-- ---- 7. 放行，归还 Redis 连接到连接池 ----
red:set_keepalive(10000, 100)