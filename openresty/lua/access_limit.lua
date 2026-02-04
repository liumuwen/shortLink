-- access_limit.lua
local redis = require "resty.redis"
local limit_req = require "resty.limit.req"

-- ================= 配置区 =================
local REDIS_HOST = "192.168.150.101"
local REDIS_PORT = 6379
local REDIS_PASSWORD = "123456"

local BLACK_LIST_TTL = 600

-- IP 令牌桶配置
local IP_RATE = 50      -- 令牌生成速率 (每秒 20 个)
local IP_BURST = 100     -- 桶容量 (允许积攒 40 个令牌，应对突发)

-- Token 令牌桶配置
local TOKEN_RATE = 5    -- 令牌生成速率 (每秒 5 个)
local TOKEN_BURST = 15  -- 桶容量 (允许积攒 15 个令牌)

-- ================= 工具函数 =================

local function get_client_ip()
    local headers = ngx.req.get_headers()
    local ip = headers["X-REAL-IP"] or headers["X-FORWARDED-FOR"] or ngx.var.remote_addr or "0.0.0.0"
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
        ngx.log(ngx.ERR, "Redis 连接失败: ", err)
        return nil
    end
    local ok, err = red:auth(REDIS_PASSWORD)
    if not ok then
        ngx.log(ngx.ERR, "Redis auth 失败: ", err)
        return nil
    end
    return red
end

-- ================= 核心逻辑 =================

local client_ip = get_client_ip()
local token = get_token()
local red = get_redis()

-- 1. 黑名单检查
if red then
    local is_black = red:get("blacklist:ip:" .. client_ip)
    if is_black == "1" then
        return ngx.exit(403)
    end
end

-- 2. 白名单检查
if red then
    local is_white = red:get("whitelist:ip:" .. client_ip)
    if is_white == "1" then
        return
    end
end

-- 3. 拉黑函数
local function ban_ip(ip)
    if red then
        red:setex("blacklist:ip:" .. ip, BLACK_LIST_TTL, "1")
    end
    ngx.log(ngx.WARN, "IP 触发令牌桶耗尽，封禁 10 分钟: ", ip)
end

-- 4. Token 令牌桶限流 (原 limit_count 已换成 limit_req)
if token then
    local lim_token, err = limit_req.new("limit_token_store", TOKEN_RATE, TOKEN_BURST)
    if not lim_token then
        ngx.log(ngx.ERR, "初始化 Token 令牌桶失败: ", err)
        return ngx.exit(500)
    end

    local delay, err = lim_token:incoming(token, true)
    if not delay then
        if err == "rejected" then
            ban_ip(client_ip)
            return ngx.exit(429)
        end
        return ngx.exit(500)
    end
    -- 注意：令牌桶模式下不执行 ngx.sleep(delay)，直接放行
end

-- 5. IP 令牌桶限流
local lim_ip, err = limit_req.new("limit_req_store", IP_RATE, IP_BURST)
if not lim_ip then
    ngx.log(ngx.ERR, "初始化 IP 令牌桶失败: ", err)
    return ngx.exit(500)
end

local delay, err = lim_ip:incoming(client_ip, true)
if not delay then
    if err == "rejected" then
        ban_ip(client_ip)
        return ngx.exit(429)
    end
    return ngx.exit(500)
end

-- 【关键修改】：去掉了 ngx.sleep(delay)
-- 只要 delay 有值（即令牌桶还没空），就立即执行，不增加响应延迟。

-- 6. Redis 连接回收
if red then
    red:set_keepalive(10000, 100)
end