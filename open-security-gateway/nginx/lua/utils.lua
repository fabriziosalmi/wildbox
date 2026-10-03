-- Wildbox Gateway Utilities Module
-- Common utility functions for Lua scripts

local cjson = require "cjson"
local http = require "resty.http"

local _M = {}

-- Logging utility with levels
function _M.log(level, message, context)
    local log_level = ngx.var.gateway_log_level or "info"
    local levels = {
        debug = 1,
        info = 2,
        warn = 3,
        error = 4
    }

    if levels[level] >= levels[log_level] then
        local log_message = message
        if context then
            log_message = message .. " | " .. cjson.encode(context)
        end

        if level == "error" then
            ngx.log(ngx.ERR, log_message)
        elseif level == "warn" then
            ngx.log(ngx.WARN, log_message)
        elseif level == "debug" then
            ngx.log(ngx.DEBUG, log_message)
        else
            ngx.log(ngx.INFO, log_message)
        end
    end
end

-- Safe JSON decode with error handling
function _M.json_decode(str)
    if not str or str == "" then
        return nil, "empty string"
    end

    local ok, result = pcall(cjson.decode, str)
    if not ok then
        return nil, "invalid json: " .. tostring(result)
    end

    return result, nil
end

-- Safe JSON encode with error handling
function _M.json_encode(obj)
    if not obj then
        return "{}", nil
    end

    local ok, result = pcall(cjson.encode, obj)
    if not ok then
        return nil, "encode error: " .. tostring(result)
    end

    return result, nil
end

-- Extract authentication token from request headers
function _M.extract_auth_token()
    -- Try Authorization header first (Bearer token)
    local auth_header = ngx.var.http_authorization
    if auth_header then
        local bearer_token = string.match(auth_header, "Bearer%s+(.+)")
        if bearer_token then
            return bearer_token, "bearer"
        end
    end

    -- Try X-API-Key header
    local api_key = ngx.var.http_x_api_key
    if api_key and api_key ~= "" then
        return api_key, "api_key"
    end

    -- Fall back to the auth_token cookie, but ONLY for safe methods.
    --
    -- Browser navigations (the standalone tools UI at /tools/<name>) carry the
    -- cookie the SPA sets at login and no Authorization header, so without this
    -- those pages could not be authenticated at all -- which is why they were
    -- previously served with no authentication whatsoever (WILDBO-AUTH-06).
    --
    -- Restricted to GET/HEAD/OPTIONS on purpose: accepting a cookie as proof of
    -- identity on a state-changing request would make every mutating endpoint
    -- CSRF-able, since a browser attaches cookies to cross-site form posts.
    local method = ngx.req.get_method()
    if method == "GET" or method == "HEAD" or method == "OPTIONS" then
        local cookie_token = ngx.var.cookie_auth_token
        if cookie_token and cookie_token ~= "" then
            return cookie_token, "bearer"
        end
    end

    return nil, "no_token"
end

-- Generate cache key for authentication data
function _M.generate_auth_cache_key(token, token_type)
    local hash = ngx.encode_base64(ngx.sha1_bin(token))
    return "auth:" .. token_type .. ":" .. hash
end

-- The `jti` claim of a JWT, or nil.
--
-- Read without verifying the signature, and only ever used as the name of a
-- revocation marker: identity has verified the token before any decision for
-- it is cached, and a forged token naming someone else's jti can at most get
-- itself refused.
function _M.jwt_jti(token)
    local segment = token:match("^[^.]+%.([^.]+)%.[^.]*$")
    if not segment then
        return nil
    end
    segment = segment:gsub("%-", "+"):gsub("_", "/")
    local remainder = #segment % 4
    if remainder > 0 then
        segment = segment .. string.rep("=", 4 - remainder)
    end
    local raw = ngx.decode_base64(segment)
    if not raw then
        return nil
    end
    local claims = _M.json_decode(raw)
    if type(claims) == "table" and type(claims.jti) == "string" and claims.jti ~= "" then
        return claims.jti
    end
    return nil
end

-- Clean sensitive headers before forwarding to backend
function _M.http_request(method, url, options)
    local httpc = http:new()

    -- Default options
    local opts = options or {}

    -- Timeouts. request_uri() does not read a `timeout` field from its
    -- params, so the caller's opts.timeout used to be ignored and every call
    -- ran with these fixed 5/10/10 s values: auth_handler's TIMEOUT_SECONDS = 5
    -- was dead configuration, and with identity unresponsive each
    -- authentication hung for 10 s instead of 5 (found by tests/chaos, #428).
    -- Honour it as the send/read budget and cap the connect at it as well.
    local timeout_ms = tonumber(opts.timeout)
    if timeout_ms then
        httpc:set_timeouts(math.min(5000, timeout_ms), timeout_ms, timeout_ms)
    else
        httpc:set_timeouts(5000, 10000, 10000) -- connect, send, read timeouts
    end
    opts.timeout = nil
    opts.method = method
    opts.headers = opts.headers or {}

    -- Add standard headers
    opts.headers["User-Agent"] = "Wildbox-Gateway/1.0"
    opts.headers["Accept"] = "application/json"

    if opts.body and type(opts.body) == "table" then
        opts.body = _M.json_encode(opts.body)
        opts.headers["Content-Type"] = "application/json"
    end

    local res, err = httpc:request_uri(url, opts)

    if not res then
        return nil, "request failed: " .. (err or "unknown error")
    end

    -- Close connection
    httpc:close()

    return res, nil
end

-- Validate team access (user belongs to team)
function _M.validate_team_access(user_id, team_id, auth_data)
    if not auth_data or not auth_data.team_id then
        return false, "no team data"
    end

    if auth_data.team_id ~= team_id then
        return false, "team mismatch"
    end

    if auth_data.user_id ~= user_id then
        return false, "user mismatch"
    end

    return true, nil
end

-- Generate request ID for tracing
function _M.generate_request_id()
    return ngx.var.request_id or string.format("%s-%s",
        os.time(),
        string.sub(ngx.encode_base64(ngx.sha1_bin(tostring(math.random()))), 1, 8)
    )
end

-- Set response headers with auth info for debugging
function _M.set_debug_headers(auth_data)
    if ngx.var.gateway_debug == "true" then
        ngx.header["X-Debug-User-ID"] = auth_data.user_id
        ngx.header["X-Debug-Team-ID"] = auth_data.team_id
        ngx.header["X-Debug-Cache-Hit"] = auth_data.cache_hit and "true" or "false"
    end
end

-- Clean sensitive headers before forwarding to backend
function _M.clean_request_headers()
    -- Remove original authorization header
    ngx.req.clear_header("Authorization")
    ngx.req.clear_header("X-API-Key")

    -- Remove any existing Wildbox headers (prevent spoofing)
    ngx.req.clear_header("X-Wildbox-User-ID")
    ngx.req.clear_header("X-Wildbox-Team-ID")
    ngx.req.clear_header("X-Wildbox-Role")
end

return _M
