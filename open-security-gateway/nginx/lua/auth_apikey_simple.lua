-- Simplified auth wrapper for API Key authentication
-- Direct validation without complex caching

ngx.log(ngx.WARN, "[AUTH] ============ auth_apikey_simple.lua LOADED ============")

local http = require "resty.http"
local cjson = require "cjson"

-- Get API key from request headers
local api_key = ngx.var.http_x_api_key

ngx.log(ngx.WARN, "[AUTH] X-API-Key header value: ", api_key or "NOT PROVIDED")

if not api_key then
    ngx.status = 401
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode({
        error = {
            code = 401,
            message = "Missing X-API-Key header",
            type = "AuthenticationError"
        }
    }))
    return ngx.exit(401)
end

-- Validate API key with Identity service
local identity_service_url = os.getenv("IDENTITY_SERVICE_URL") or "http://open-security-identity:8001"
local gateway_secret = os.getenv("GATEWAY_INTERNAL_SECRET") or ""

ngx.log(ngx.WARN, "[AUTH] Validating API key with Identity service: ", identity_service_url)

local httpc = http.new()
httpc:set_timeout(5000) -- 5 second timeout

local auth_url = identity_service_url .. "/internal/authorize"
ngx.log(ngx.WARN, "[AUTH] Calling: ", auth_url)

local res, err = httpc:request_uri(auth_url, {
    method = "POST",
    body = cjson.encode({
        token = api_key,
        token_type = "api_key"
    }),
    headers = {
        ["Content-Type"] = "application/json",
        ["X-Gateway-Secret"] = gateway_secret
    }
})

ngx.log(ngx.WARN, "[AUTH] Response status: ", res and res.status or "nil", " error: ", err or "none")

if err then
    ngx.log(ngx.ERR, "Failed to connect to identity service: ", err)
    ngx.status = 503
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode({
        error = {
            code = 503,
            message = "Authentication service unavailable",
            type = "ServiceError"
        }
    }))
    return ngx.exit(503)
end

if res.status ~= 200 then
    ngx.log(ngx.WARN, "API key validation failed: ", res.status, " ", res.body or "no body")
    ngx.status = 401
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode({
        error = {
            code = 401,
            message = "Invalid API key",
            type = "AuthenticationError"
        }
    }))
    return ngx.exit(401)
end

-- Parse response and set headers
local auth_data = cjson.decode(res.body)

ngx.req.set_header("X-Wildbox-User-ID", auth_data.user_id)
ngx.req.set_header("X-Wildbox-Team-ID", auth_data.team_id)
ngx.req.set_header("X-Wildbox-Plan", auth_data.plan or "free")
ngx.req.set_header("X-Wildbox-Role", auth_data.role or "user")

ngx.log(ngx.INFO, "API key authenticated for user: ", auth_data.user_id, " team: ", auth_data.team_id)
