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
-- Returns the JSON text alone on success, so ngx.say(utils.json_encode(x))
-- writes exactly that text. It used to return (text, nil), and ngx.say prints
-- every argument: each JSON error body the gateway wrote ended in "nil" and
-- was not valid JSON (#571). On failure: nil and the error.
function _M.json_encode(obj)
    if not obj then
        return "{}"
    end

    local ok, result = pcall(cjson.encode, obj)
    if not ok then
        return nil, "encode error: " .. tostring(result)
    end

    return result
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

    -- No cookie fallback. The auth_token cookie was accepted on safe methods
    -- for the standalone tools UI's page loads at /tools/ (WILDBO-AUTH-06),
    -- which carried no Authorization header. That UI is removed (#581), and
    -- the dashboard reads the cookie itself and sends it as a Bearer token,
    -- so a cookie alone is not a credential here.
    return nil, "no_token"
end

-- Generate cache key for authentication data
function _M.generate_auth_cache_key(token, token_type)
    local hash = ngx.encode_base64(ngx.sha1_bin(token))
    return "auth:" .. token_type .. ":" .. hash
end

-- The claims of a JWT, decoded but NOT verified, or nil.
--
-- Only ever read for a token identity has verified: a decision is cached
-- under a key derived from the whole token, so a token whose claims were
-- altered is a different token that identity refuses.
local function jwt_claims(token)
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
    if type(claims) ~= "table" then
        return nil
    end
    return claims
end

-- The `jti` claim of a JWT, or nil.
--
-- Read without verifying the signature, and only ever used as the name of a
-- revocation marker: identity has verified the token before any decision for
-- it is cached, and a forged token naming someone else's jti can at most get
-- itself refused.
function _M.jwt_jti(token)
    local claims = jwt_claims(token)
    if claims and type(claims.jti) == "string" and claims.jti ~= "" then
        return claims.jti
    end
    return nil
end

-- The `iat` claim of a JWT (seconds, possibly fractional), or nil.
--
-- Compared with the cutoff a password change records for the token's user
-- (#569); see jwt_claims() for why reading it unverified is safe.
function _M.jwt_iat(token)
    local claims = jwt_claims(token)
    if claims and type(claims.iat) == "number" then
        return claims.iat
    end
    return nil
end

-- Clean sensitive headers before forwarding to backend
-- Errors that mean the peer closed a kept-alive connection under us, not
-- that the service is down: the request was written to (or read from) a
-- pooled socket the server had just timed out (#609).
local STALE_CONNECTION_ERRORS = {
    ["closed"] = true,
    ["broken pipe"] = true,
    ["connection reset by peer"] = true,
}

function _M.is_stale_connection_error(err)
    return err ~= nil and STALE_CONNECTION_ERRORS[err] == true
end

-- How long a connection to a service may sit idle in the gateway's pool.
-- Below the 5 s keep-alive uvicorn closes idle connections after, so the
-- gateway gives up a connection before the service does and never writes
-- a request into one the service is closing (#609). lua-resty-http would
-- otherwise use lua_socket_keepalive_timeout, 60 s by default.
_M.UPSTREAM_KEEPALIVE_MS = 4000

local function new_client(timeout_ms)
    local httpc = http:new()
    -- Timeouts. request_uri() does not read a `timeout` field from its
    -- params, so the caller's opts.timeout used to be ignored and every call
    -- ran with these fixed 5/10/10 s values: auth_handler's TIMEOUT_SECONDS = 5
    -- was dead configuration, and with identity unresponsive each
    -- authentication hung for 10 s instead of 5 (found by tests/chaos, #428).
    -- Honour it as the send/read budget and cap the connect at it as well.
    if timeout_ms then
        httpc:set_timeouts(math.min(5000, timeout_ms), timeout_ms, timeout_ms)
    else
        httpc:set_timeouts(5000, 10000, 10000) -- connect, send, read timeouts
    end
    return httpc
end

-- opts.retry_stale: the request is idempotent and may be sent once more, on
-- another connection, when the first one turns out to have been closed by
-- the server (STALE_CONNECTION_ERRORS). Only the caller knows that.
function _M.http_request(method, url, options)
    -- Default options
    local opts = options or {}

    local timeout_ms = tonumber(opts.timeout)
    local retry_stale = opts.retry_stale == true
    opts.timeout = nil
    opts.retry_stale = nil
    opts.keepalive_timeout = opts.keepalive_timeout or _M.UPSTREAM_KEEPALIVE_MS
    opts.method = method
    opts.headers = opts.headers or {}

    -- Add standard headers
    opts.headers["User-Agent"] = "Wildbox-Gateway/1.0"
    opts.headers["Accept"] = "application/json"

    if opts.body and type(opts.body) == "table" then
        opts.body = _M.json_encode(opts.body)
        opts.headers["Content-Type"] = "application/json"
    end

    -- request_uri() hands the connection back to the pool itself (or closes
    -- it); nothing is left to close here.
    local res, err = new_client(timeout_ms):request_uri(url, opts)

    if not res and retry_stale and _M.is_stale_connection_error(err) then
        _M.log("warn", "Upstream closed a kept-alive connection; retrying once", {
            error = err,
            url = url
        })
        res, err = new_client(timeout_ms):request_uri(url, opts)
    end

    if not res then
        return nil, "request failed: " .. (err or "unknown error")
    end

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
