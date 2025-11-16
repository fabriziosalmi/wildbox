-- Wildbox Gateway Authentication Handler - IMPROVED VERSION
-- Phase 1 Blueprint Implementation: Enhanced security, performance, and error handling

local utils = require "utils"
local cjson = require "cjson"

local _M = {}

-- Configuration constants (Blueprint Phase 1 - Remove hardcoded values)
local CACHE_TTL = 300 -- 5 minutes as per blueprint
local MAX_RETRIES = 3
local TIMEOUT_SECONDS = 5
local CIRCUIT_BREAKER_THRESHOLD = 10
local CIRCUIT_BREAKER_TIMEOUT = 60

-- Rate limits per plan (requests per hour) - Blueprint specified limits
local RATE_LIMITS = {
    free = 1000,      -- 1,000/hour
    personal = 100000, -- 100,000/hour  
    business = 1000000 -- 1,000,000/hour
}

-- Get gateway configuration from environment variables
local function get_config()
    local config_cache = ngx.shared.config_cache
    
    -- Handle case where shared dict is not available
    if not config_cache then
        utils.log("error", "config_cache shared dictionary not available")
        -- Return default config without caching
        return {
            identity_service_url = os.getenv("IDENTITY_SERVICE_URL") or "http://open-security-identity:8001",
            gateway_secret = os.getenv("GATEWAY_INTERNAL_SECRET") or "",
            cache_ttl = tonumber(os.getenv("AUTH_CACHE_TTL")) or CACHE_TTL,
            debug_mode = os.getenv("GATEWAY_DEBUG") == "true"
        }
    end
    
    local config_json = config_cache:get("gateway_config")
    
    if not config_json then
        -- Build config from environment variables (Blueprint security requirement)
        local config = {
            identity_service_url = os.getenv("IDENTITY_SERVICE_URL") or "http://open-security-identity:8000",
            gateway_secret = os.getenv("GATEWAY_INTERNAL_SECRET") or ngx.log(ngx.ERR, "GATEWAY_INTERNAL_SECRET not set"),
            cache_ttl = tonumber(os.getenv("AUTH_CACHE_TTL")) or CACHE_TTL,
            debug_mode = os.getenv("GATEWAY_DEBUG") == "true"
        }
        
        -- Cache config for 1 hour
        config_json = utils.json_encode(config)
        config_cache:set("gateway_config", config_json, 3600)
        
        utils.log("info", "Gateway configuration loaded from environment")
        return config
    end
    
    local config, err = utils.json_decode(config_json)
    if err then
        utils.log("error", "Failed to decode gateway config", {error = err})
        return nil
    end
    
    return config
end

-- Circuit breaker for identity service calls
local function check_circuit_breaker()
    local circuit_cache = ngx.shared.auth_cache
    local failures_key = "circuit_breaker:failures"
    local last_failure_key = "circuit_breaker:last_failure"
    
    local failures = circuit_cache:get(failures_key) or 0
    local last_failure = circuit_cache:get(last_failure_key) or 0
    local now = ngx.time()
    
    -- Circuit open - too many failures
    if failures >= CIRCUIT_BREAKER_THRESHOLD then
        if now - last_failure < CIRCUIT_BREAKER_TIMEOUT then
            utils.log("warn", "Circuit breaker OPEN - identity service unavailable", {
                failures = failures,
                timeout_remaining = CIRCUIT_BREAKER_TIMEOUT - (now - last_failure)
            })
            return false
        else
            -- Reset circuit breaker
            circuit_cache:delete(failures_key)
            circuit_cache:delete(last_failure_key)
            utils.log("info", "Circuit breaker RESET - attempting identity service call")
        end
    end
    
    return true
end

-- Record circuit breaker failure
local function record_circuit_breaker_failure()
    local circuit_cache = ngx.shared.auth_cache
    local failures_key = "circuit_breaker:failures"
    local last_failure_key = "circuit_breaker:last_failure"
    
    local failures = (circuit_cache:get(failures_key) or 0) + 1
    circuit_cache:set(failures_key, failures, CIRCUIT_BREAKER_TIMEOUT)
    circuit_cache:set(last_failure_key, ngx.time(), CIRCUIT_BREAKER_TIMEOUT)
    
    utils.log("warn", "Circuit breaker failure recorded", {failures = failures})
end

-- Call identity service to validate token with improved error handling
local function validate_token_with_identity(token, token_type, config)
    -- Check circuit breaker
    if not check_circuit_breaker() then
        return nil, "circuit_breaker_open"
    end
    
    local url = config.identity_service_url .. "/internal/authorize"
    
    local request_body = {
        token = token,
        token_type = token_type,
        request_path = ngx.var.uri,
        request_method = ngx.var.request_method,
        client_ip = ngx.var.remote_addr,
        user_agent = ngx.var.http_user_agent,
        timestamp = ngx.time()
    }
    
    utils.log("debug", "Calling identity service for token validation", {
        url = url,
        token_type = token_type,
        path = ngx.var.uri
    })
    
    local start_time = ngx.now()
    
    local res, err = utils.http_request("POST", url, {
        body = request_body,
        headers = {
            ["Content-Type"] = "application/json",
            ["X-Gateway-Secret"] = config.gateway_secret,
            ["X-Request-ID"] = ngx.var.request_id or utils.generate_request_id()
        },
        timeout = TIMEOUT_SECONDS * 1000 -- Convert to milliseconds
    })
    
    local duration = (ngx.now() - start_time) * 1000
    
    if err then
        utils.log("error", "Failed to call identity service", {
            error = err,
            duration_ms = duration,
            url = url
        })
        record_circuit_breaker_failure()
        return nil, "identity_service_error"
    end
    
    if res.status == 200 then
        local auth_data, decode_err = utils.json_decode(res.body)
        if decode_err then
            utils.log("error", "Failed to decode identity response", {
                error = decode_err,
                body = res.body
            })
            return nil, "invalid_response"
        end
        
        -- Add metadata
        auth_data.validated_at = ngx.time()
        auth_data.response_time_ms = duration
        
        utils.log("debug", "Token validation successful", {
            user_id = auth_data.user_id,
            team_id = auth_data.team_id,
            plan = auth_data.plan,
            duration_ms = duration
        })
        
        return auth_data, nil
    elseif res.status == 401 then
        utils.log("debug", "Token validation failed - unauthorized")
        return nil, "unauthorized"
    elseif res.status == 403 then
        utils.log("debug", "Token validation failed - forbidden")
        return nil, "forbidden"
    elseif res.status == 429 then
        utils.log("warn", "Identity service rate limited")
        return nil, "rate_limited"
    else
        utils.log("error", "Identity service returned unexpected status", {
            status = res.status,
            body = res.body,
            duration_ms = duration
        })
        record_circuit_breaker_failure()
        return nil, "identity_service_error"
    end
end

-- Improved cache operations with TTL (Blueprint requirement: 1-5 minute TTL)
local function get_cached_auth_data(cache_key, config)
    local auth_cache = ngx.shared.auth_cache
    local cached_data = auth_cache:get(cache_key)
    
    if cached_data then
        local auth_data, err = utils.json_decode(cached_data)
        if not err then
            local now = ngx.time()
            if auth_data.expires_at and auth_data.expires_at > now then
                auth_data.cache_hit = true
                utils.log("debug", "Using cached auth data", {
                    user_id = auth_data.user_id,
                    ttl_remaining = auth_data.expires_at - now
                })
                return auth_data, nil
            else
                -- Expired cache entry
                auth_cache:delete(cache_key)
                utils.log("debug", "Cache entry expired and removed", {cache_key = cache_key})
            end
        end
    end
    
    return nil, "cache_miss"
end

-- Set authentication data in cache with proper TTL
local function set_cached_auth_data(cache_key, auth_data, config)
    local auth_cache = ngx.shared.auth_cache
    local ttl = config.cache_ttl or CACHE_TTL
    
    -- Set expiration time
    auth_data.expires_at = ngx.time() + ttl
    auth_data.cache_hit = false
    
    local cached_data = utils.json_encode(auth_data)
    local success, err = auth_cache:set(cache_key, cached_data, ttl)
    
    if not success then
        utils.log("warn", "Failed to cache auth data", {error = err})
    else
        utils.log("debug", "Auth data cached successfully", {
            cache_key = cache_key,
            ttl = ttl
        })
    end
end

-- Enhanced rate limiting with sliding window (Blueprint requirement)
local function apply_rate_limiting(auth_data)
    local plan = auth_data.plan or "free"
    local team_id = auth_data.team_id
    local limit_per_hour = RATE_LIMITS[plan] or RATE_LIMITS.free
    
    -- Convert to requests per second for sliding window
    local limit_per_second = limit_per_hour / 3600
    local window_size = 60 -- 1 minute sliding window
    
    local rate_cache = ngx.shared.rate_limit_cache
    local key = "rate:" .. team_id .. ":" .. plan
    local now = ngx.time()
    
    -- Get current request timestamps
    local current_data = rate_cache:get(key)
    local requests = {}
    
    if current_data then
        local decoded_data, err = utils.json_decode(current_data)
        if not err and decoded_data.requests then
            requests = decoded_data.requests
        end
    end
    
    -- Remove requests outside the sliding window
    local filtered_requests = {}
    for _, timestamp in ipairs(requests) do
        if now - timestamp < window_size then
            table.insert(filtered_requests, timestamp)
        end
    end
    
    -- Add current request
    table.insert(filtered_requests, now)
    
    -- Check if limit exceeded
    local requests_in_window = #filtered_requests
    local max_requests = limit_per_second * window_size
    
    if requests_in_window > max_requests then
        utils.log("warn", "Rate limit exceeded", {
            team_id = team_id,
            plan = plan,
            current_requests = requests_in_window,
            limit = max_requests,
            window_size = window_size
        })
        
        ngx.status = ngx.HTTP_TOO_MANY_REQUESTS
        ngx.header.content_type = "application/json"
        ngx.header["Retry-After"] = tostring(window_size)
        ngx.header["X-RateLimit-Limit"] = tostring(limit_per_hour)
        ngx.header["X-RateLimit-Remaining"] = tostring(math.max(0, max_requests - requests_in_window))
        ngx.header["X-RateLimit-Reset"] = tostring(now + window_size)
        
        ngx.say(utils.json_encode({
            error = "rate_limit_exceeded",
            message = "Rate limit exceeded for plan: " .. plan,
            limit_per_hour = limit_per_hour,
            retry_after_seconds = window_size
        }))
        ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
    end
    
    -- Update cache with new request list
    local updated_data = {requests = filtered_requests}
    rate_cache:set(key, utils.json_encode(updated_data), window_size)
    
    -- Set rate limit headers
    ngx.header["X-RateLimit-Limit"] = tostring(limit_per_hour)
    ngx.header["X-RateLimit-Remaining"] = tostring(math.max(0, max_requests - requests_in_window))
    ngx.header["X-RateLimit-Reset"] = tostring(now + window_size)
end

-- Set authentication headers for backend services
local function set_auth_headers(auth_data)
    ngx.var.wildbox_user_id = auth_data.user_id or ""
    ngx.var.wildbox_team_id = auth_data.team_id or ""
    ngx.var.wildbox_plan = auth_data.plan or "free"
    ngx.var.wildbox_role = auth_data.role or "user"
    
    -- Set headers for backend services
    ngx.req.set_header("X-Wildbox-User-ID", auth_data.user_id)
    ngx.req.set_header("X-Wildbox-Team-ID", auth_data.team_id)
    ngx.req.set_header("X-Wildbox-Plan", auth_data.plan)
    ngx.req.set_header("X-Wildbox-Role", auth_data.role)
    
    -- Response headers for client
    ngx.header["X-Wildbox-Plan"] = auth_data.plan
    ngx.header["X-Wildbox-Team-ID"] = auth_data.team_id
end

-- Main authentication handler
function _M.authenticate()
    local request_start = ngx.now()
    
    -- Get configuration
    local config = get_config()
    if not config then
        utils.log("error", "Gateway configuration not available")
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    
    -- Extract authentication token
    local auth_header = ngx.var.http_authorization
    local token, token_type = utils.extract_auth_token(auth_header)
    
    if not token then
        utils.log("debug", "No authentication token provided")
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.header.content_type = "application/json"
        ngx.header["WWW-Authenticate"] = 'Bearer realm="Wildbox API"'
        ngx.say(utils.json_encode({
            error = "authentication_required",
            message = "Valid authentication token required"
        }))
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
                ngx.status = ngx.HTTP_UNAUTHORIZED
                ngx.header.content_type = "application/json"
                ngx.say(utils.json_encode({
                    error = "invalid_token",
                    message = "Authentication token is invalid or expired"
                }))
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
            elseif validation_err == "forbidden" then
                ngx.exit(ngx.HTTP_FORBIDDEN)
            elseif validation_err == "circuit_breaker_open" then
                ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
                ngx.header.content_type = "application/json"
                ngx.say(utils.json_encode({
                    error = "service_unavailable",
                    message = "Authentication service temporarily unavailable"
                }))
                ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
            else
                utils.log("error", "Authentication service error", {error = validation_err})
                ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
            end
        end
        
        -- Cache the validation result
        set_cached_auth_data(cache_key, auth_data, config)
    end
    
    -- Apply rate limiting
    apply_rate_limiting(auth_data)
    
    -- Set authentication headers for backend services
    set_auth_headers(auth_data)
    
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
