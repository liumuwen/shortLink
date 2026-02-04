-- access_limit.lua
local redis = require "resty.redis"
local limit_req = require "resty.limit.req"
local limit_count = require "resty.limit.count"

-- ================= 配置区 =================
local REDIS_HOST = "192.168.150.101"
local REDIS_PORT = 6379
local REDIS_PASSWORD = "123456"

local BLACK_LIST_TTL = 600
local IP_RATE = 20
local IP_BURST = 10
local TOKEN_RATE = 100

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

-- ✅ 修复：正确返回 redis 对象
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

-- 1. 黑名单检查（✅ red 判空）
if red then
    local is_black = red:get("blacklist:ip:" .. client_ip)
    if is_black == "1" then
        return ngx.exit(403)
    end
end

-- 2. 白名单检查（✅ red 判空）
if red then
    local is_white = red:get("whitelist:ip:" .. client_ip)
    if is_white == "1" then
        return
    end
end

-- 3. 拉黑函数（✅ red 判空）
local function ban_ip(ip)
    if red then
        red:setex("blacklist:ip:" .. ip, BLACK_LIST_TTL, "1")
    end
    ngx.log(ngx.WARN, "IP 被封禁 10 分钟: ", ip)
end

-- 4. Token 限流
if token then
    local lim_token, err = limit_count.new("limit_token_store", TOKEN_RATE, 60)
    if not lim_token then
        ngx.log(ngx.ERR, "初始化 Token 限流失败: ", err)
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
end

-- 5. IP 限流
local lim_ip, err = limit_req.new("limit_req_store", IP_RATE, IP_BURST)
if not lim_ip then
    ngx.log(ngx.ERR, "初始化 IP 限流失败: ", err)
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

-- 6. 漏桶 delay
if delay >= 0.001 then
    ngx.sleep(delay)
end

-- 7. Redis 连接回收（✅ red 判空）
if red then
    red:set_keepalive(10000, 100)
end
