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
    
    -- Try query parameter (less secure, for specific endpoints only)
    local args = ngx.req.get_uri_args()
    if args.token then
        return args.token, "query"
    end
    
    return nil, "no_token"
end

-- Generate cache key for authentication data
function _M.generate_auth_cache_key(token, token_type)
    local hash = ngx.encode_base64(ngx.sha1_bin(token))
    return "auth:" .. token_type .. ":" .. hash
end

-- Check if a plan allows access to a specific feature
function _M.plan_allows_feature(plan, feature)
    local plan_features = {
        free = {
            "dashboard", "basic_monitoring", "data_feeds"
        },
        personal = {
            "dashboard", "basic_monitoring", "data_feeds", 
            "cspm", "guardian", "sensor"
        },
        business = {
            "dashboard", "basic_monitoring", "data_feeds",
            "cspm", "guardian", "sensor", "responder", "automations"
        },
        enterprise = {
            "dashboard", "basic_monitoring", "data_feeds",
            "cspm", "guardian", "sensor", "responder", "automations", "agents"
        }
    }
    
    local features = plan_features[plan]
    if not features then
        return false
    end
    
    for _, allowed_feature in ipairs(features) do
        if allowed_feature == feature then
            return true
        end
    end
    
    return false
end

-- Clean sensitive headers before forwarding to backend
function _M.http_request(method, url, options)
    local httpc = http:new()
    
    -- Set timeouts
    httpc:set_timeouts(5000, 10000, 10000) -- connect, send, read timeouts
    
    -- Default options
    local opts = options or {}
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
        ngx.header["X-Debug-Plan"] = auth_data.plan
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
    ngx.req.clear_header("X-Wildbox-Plan")
    ngx.req.clear_header("X-Wildbox-Role")
end

return _M
