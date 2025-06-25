-- Wildbox Gateway Authentication Handler
-- Centralized authentication and authorization logic

local utils = require "utils"
local cjson = require "cjson"

local _M = {}

-- Get gateway configuration from shared dict
local function get_config()
    local config_cache = ngx.shared.config_cache
    local config_json = config_cache:get("gateway_config")
    
    if not config_json then
        utils.log("error", "Gateway configuration not found")
        return nil
    end
    
    local config, err = utils.json_decode(config_json)
    if err then
        utils.log("error", "Failed to decode gateway config", {error = err})
        return nil
    end
    
    return config
end

-- Call identity service to validate token
local function validate_token_with_identity(token, token_type, config)
    local url = config.identity_service_url .. "/internal/authorize"
    
    local request_body = {
        token = token,
        token_type = token_type,
        request_path = ngx.var.uri,
        request_method = ngx.var.request_method,
        client_ip = ngx.var.remote_addr,
        user_agent = ngx.var.http_user_agent
    }
    
    utils.log("debug", "Calling identity service for token validation", {
        url = url,
        token_type = token_type,
        path = ngx.var.uri
    })
    
    local res, err = utils.http_request("POST", url, {
        body = request_body,
        headers = {
            ["Content-Type"] = "application/json",
            ["X-Gateway-Secret"] = "gateway-internal-secret" -- TODO: Use proper secret
        }
    })
    
    if err then
        utils.log("error", "Failed to call identity service", {error = err})
        return nil, "identity_service_error"
    end
    
    if res.status == 200 then
        local auth_data, decode_err = utils.json_decode(res.body)
        if decode_err then
            utils.log("error", "Failed to decode identity response", {error = decode_err})
            return nil, "invalid_response"
        end
        
        utils.log("debug", "Token validation successful", {
            user_id = auth_data.user_id,
            team_id = auth_data.team_id,
            plan = auth_data.plan
        })
        
        return auth_data, nil
    elseif res.status == 401 then
        utils.log("debug", "Token validation failed - unauthorized")
        return nil, "unauthorized"
    elseif res.status == 403 then
        utils.log("debug", "Token validation failed - forbidden")
        return nil, "forbidden"
    else
        utils.log("error", "Identity service returned unexpected status", {
            status = res.status,
            body = res.body
        })
        return nil, "identity_service_error"
    end
end

-- Get or set authentication data in cache
local function get_cached_auth_data(cache_key, config)
    local auth_cache = ngx.shared.auth_cache
    local cached_data = auth_cache:get(cache_key)
    
    if cached_data then
        local auth_data, err = utils.json_decode(cached_data)
        if not err then
            -- Check if cache entry is still valid
            local now = ngx.time()
            if auth_data.expires_at and auth_data.expires_at > now then
                utils.log("debug", "Using cached auth data", {
                    user_id = auth_data.user_id,
                    expires_in = auth_data.expires_at - now
                })
                auth_data.cache_hit = true
                return auth_data, nil
            else
                utils.log("debug", "Cached auth data expired, removing from cache")
                auth_cache:delete(cache_key)
            end
        end
    end
    
    return nil, "cache_miss"
end

-- Set authentication data in cache
local function set_cached_auth_data(cache_key, auth_data, config)
    local auth_cache = ngx.shared.auth_cache
    local ttl = config.auth_cache_ttl or 300
    
    -- Add expiration timestamp
    auth_data.expires_at = ngx.time() + ttl
    auth_data.cache_hit = false
    
    local cached_json, err = utils.json_encode(auth_data)
    if err then
        utils.log("warn", "Failed to encode auth data for cache", {error = err})
        return
    end
    
    local success, cache_err = auth_cache:set(cache_key, cached_json, ttl)
    if not success then
        utils.log("warn", "Failed to cache auth data", {error = cache_err})
    else
        utils.log("debug", "Auth data cached successfully", {
            ttl = ttl,
            user_id = auth_data.user_id
        })
    end
end

-- Apply rate limiting based on user plan
local function apply_rate_limiting(auth_data)
    local plan = auth_data.plan or "free"
    local team_id = auth_data.team_id
    
    if not team_id then
        utils.log("warn", "No team_id for rate limiting")
        return
    end
    
    -- Get rate limits per plan (requests per second)
    local rate_limits = {
        free = 10,
        personal = 50,
        business = 200,
        enterprise = 1000
    }
    
    local limit = rate_limits[plan] or rate_limits.free
    
    -- Use lua-resty-limit-req for dynamic rate limiting
    -- For now, we'll implement a simple sliding window in shared dict
    local rate_cache = ngx.shared.rate_limit_cache
    local key = "rate:" .. team_id
    local window = 60 -- 1 minute window
    local now = ngx.time()
    
    -- Get current count
    local current_data = rate_cache:get(key)
    local requests = {}
    
    if current_data then
        local decoded_data, err = utils.json_decode(current_data)
        if not err then
            requests = decoded_data.requests or {}
        end
    end
    
    -- Remove old requests outside the window
    local filtered_requests = {}
    for _, timestamp in ipairs(requests) do
        if now - timestamp < window then
            table.insert(filtered_requests, timestamp)
        end
    end
    
    -- Check if limit exceeded
    local max_requests = limit * window -- requests per minute
    if #filtered_requests >= max_requests then
        utils.log("warn", "Rate limit exceeded", {
            team_id = team_id,
            plan = plan,
            current_requests = #filtered_requests,
            limit = max_requests
        })
        ngx.status = ngx.HTTP_TOO_MANY_REQUESTS
        ngx.header.content_type = "application/json"
        ngx.say(utils.json_encode({
            error = "rate_limit_exceeded",
            message = "Too many requests",
            plan = plan,
            limit_per_minute = max_requests,
            retry_after = 60
        }))
        ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
    end
    
    -- Add current request
    table.insert(filtered_requests, now)
    
    -- Store updated data
    local updated_data = {
        requests = filtered_requests,
        updated_at = now
    }
    
    local encoded_data, encode_err = utils.json_encode(updated_data)
    if not encode_err then
        rate_cache:set(key, encoded_data, window)
    end
    
    utils.log("debug", "Rate limit check passed", {
        plan = plan,
        team_id = team_id,
        current_requests = #filtered_requests,
        limit = max_requests
    })
end

-- Set authentication headers for backend services
local function set_auth_headers(auth_data)
    -- Clean any existing headers first
    utils.clean_request_headers()
    
    -- Set Wildbox authentication headers
    ngx.var.wildbox_user_id = auth_data.user_id or ""
    ngx.var.wildbox_team_id = auth_data.team_id or ""
    ngx.var.wildbox_plan = auth_data.plan or ""
    ngx.var.wildbox_role = auth_data.role or ""
    
    -- Set headers for backend services
    ngx.req.set_header("X-Wildbox-User-ID", auth_data.user_id)
    ngx.req.set_header("X-Wildbox-Team-ID", auth_data.team_id)
    ngx.req.set_header("X-Wildbox-Plan", auth_data.plan)
    ngx.req.set_header("X-Wildbox-Role", auth_data.role)
    ngx.req.set_header("X-Request-ID", utils.generate_request_id())
    
    utils.log("debug", "Set authentication headers", {
        user_id = auth_data.user_id,
        team_id = auth_data.team_id,
        plan = auth_data.plan
    })
end

-- Check feature access based on plan and path
local function check_feature_access(auth_data)
    local uri = ngx.var.uri
    local plan = auth_data.plan or "free"
    
    -- Define feature mappings
    local feature_patterns = {
        {pattern = "^/api/v1/cspm/", feature = "cspm"},
        {pattern = "^/api/v1/responder/", feature = "responder"},
        {pattern = "^/api/v1/agents/", feature = "agents"},
        {pattern = "^/api/v1/automations/", feature = "automations"}
    }
    
    for _, mapping in ipairs(feature_patterns) do
        if string.match(uri, mapping.pattern) then
            if not utils.plan_allows_feature(plan, mapping.feature) then
                utils.log("info", "Feature access denied", {
                    feature = mapping.feature,
                    plan = plan,
                    user_id = auth_data.user_id,
                    uri = uri
                })
                return false, mapping.feature
            end
        end
    end
    
    return true, nil
end

-- Main authorization function
function _M.authorize()
    local request_start = ngx.now()
    
    -- Get configuration
    local config = get_config()
    if not config then
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    
    -- Extract authentication token
    local token, token_type = utils.extract_auth_token()
    if not token then
        utils.log("debug", "No authentication token provided")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
    
    -- Generate cache key
    local cache_key = utils.generate_auth_cache_key(token, token_type)
    
    -- Try to get auth data from cache first
    local auth_data, cache_err = get_cached_auth_data(cache_key, config)
    
    -- If not in cache, validate with identity service
    if cache_err == "cache_miss" then
        local validation_err
        auth_data, validation_err = validate_token_with_identity(token, token_type, config)
        
        if validation_err then
            if validation_err == "unauthorized" then
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
            elseif validation_err == "forbidden" then
                ngx.exit(ngx.HTTP_FORBIDDEN)
            else
                utils.log("error", "Authentication service error", {error = validation_err})
                ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
            end
        end
        
        -- Cache the validation result
        set_cached_auth_data(cache_key, auth_data, config)
    end
    
    -- Check feature access based on plan
    local access_allowed, blocked_feature = check_feature_access(auth_data)
    if not access_allowed then
        ngx.status = ngx.HTTP_PAYMENT_REQUIRED
        ngx.header.content_type = "application/json"
        ngx.say(utils.json_encode({
            error = "feature_not_available",
            message = "This feature requires a higher plan",
            feature = blocked_feature,
            current_plan = auth_data.plan,
            upgrade_url = "/upgrade"
        }))
        ngx.exit(ngx.HTTP_PAYMENT_REQUIRED)
    end
    
    -- Apply rate limiting
    apply_rate_limiting(auth_data)
    
    -- Set authentication headers for backend services
    set_auth_headers(auth_data)
    
    -- Set debug headers if enabled
    utils.set_debug_headers(auth_data)
    
    local request_time = (ngx.now() - request_start) * 1000
    utils.log("debug", "Authorization completed", {
        user_id = auth_data.user_id,
        team_id = auth_data.team_id,
        plan = auth_data.plan,
        cache_hit = auth_data.cache_hit,
        duration_ms = request_time
    })
end

return _M
