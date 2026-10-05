-- Wildbox Gateway Authentication Handler - IMPROVED VERSION
-- Phase 1 Blueprint Implementation: Enhanced security, performance, and error handling

local utils = require "utils"

local _M = {}

-- Configuration constants (Blueprint Phase 1 - Remove hardcoded values)
local CACHE_TTL = 300 -- 5 minutes as per blueprint
local TIMEOUT_SECONDS = 5
local CIRCUIT_BREAKER_THRESHOLD = 10
local CIRCUIT_BREAKER_TIMEOUT = 60

-- Flat per-team rate limit (requests per hour). Plan-based tiers were removed
-- with billing/subscriptions; this is abuse protection on top of the per-IP
-- limit_req zones in nginx.conf.
-- Per-team request budget. This was 1000000/hour -- 16,666 per minute -- which
-- no client reaches, so the only per-tenant admission control in the system
-- never engaged and one team could consume the whole capacity within the per-IP
-- ceiling (WILDBO-SCAL-03). 10,000/hour is roughly 2.8 req/s sustained per team,
-- comfortable for interactive use and for the dashboard's polling.
local DEFAULT_RATE_LIMIT_PER_HOUR = 10000
-- Far above any real budget; it keeps the value an exact integer, and a
-- typo with extra digits is refused instead of turning the limit off.
local MAX_RATE_LIMIT_PER_HOUR = 1000000000

-- RATE_LIMIT_PER_HOUR (#627). Unset means the default above. Set, it must be
-- a positive integer: anything else -- "0", "-5", "10k", "1.5", an empty
-- string -- used to become the default through `tonumber(...) or 10000`,
-- so a mistyped limit was replaced by another one without a word. It is now
-- refused, and with it the configuration: the module is loaded by
-- init_by_lua in nginx.conf, where an error stops nginx from starting.
-- `nginx -t` does not run init_by_lua and does not catch a bad value.
function _M.parse_rate_limit_per_hour(raw)
    if raw == nil then
        return DEFAULT_RATE_LIMIT_PER_HOUR
    end
    if type(raw) == "string" and raw:match("^[1-9]%d*$") and #raw <= 10 then
        local value = tonumber(raw)
        if value <= MAX_RATE_LIMIT_PER_HOUR then
            return value
        end
    end
    return nil, string.format(
        "RATE_LIMIT_PER_HOUR must be a whole number of requests per hour between 1 and %d, got %q",
        MAX_RATE_LIMIT_PER_HOUR, string.sub(tostring(raw), 1, 64))
end

-- Read where the module is loaded: init_by_lua, in the master process. The
-- variable must still be declared with `env` in nginx.conf: nginx hands a
-- process only the variables declared there, and the master is the one
-- exception only until it is replaced (a binary upgrade starts the new
-- master with the declared variables alone). scripts/check_gateway_config.py
-- fails CI for any variable read here and not declared.
local RATE_LIMIT_PER_HOUR, RATE_LIMIT_ERROR = _M.parse_rate_limit_per_hour(os.getenv("RATE_LIMIT_PER_HOUR"))
if not RATE_LIMIT_PER_HOUR then
    error(RATE_LIMIT_ERROR, 0)
end

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
            identity_service_url = os.getenv("IDENTITY_SERVICE_URL") or "http://open-security-identity:8001",
            gateway_secret = os.getenv("GATEWAY_INTERNAL_SECRET") or "",
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
            local remaining = CIRCUIT_BREAKER_TIMEOUT - (now - last_failure)
            utils.log("warn", "Circuit breaker OPEN - identity service unavailable", {
                failures = failures,
                timeout_remaining = remaining
            })
            return false, remaining
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
    local closed, retry_after = check_circuit_breaker()
    if not closed then
        return nil, "circuit_breaker_open", retry_after
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
        timeout = TIMEOUT_SECONDS * 1000, -- Convert to milliseconds
        -- Authorizing is a read: identity changes nothing for it, so a
        -- request that met a connection identity had just closed can be
        -- sent again (#609).
        retry_stale = true
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
local function get_cached_auth_data(cache_key)
    local auth_cache = ngx.shared.auth_cache
    local cached_data = auth_cache:get(cache_key)

    if cached_data then
        local auth_data, err = utils.json_decode(cached_data)
        if not err then
            local now = ngx.now()
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

-- Revocation (#571).
--
-- Nothing could invalidate the cache: disabling a user, deleting an API key,
-- changing a role or removing a team membership all took effect only when the
-- 5-minute entry expired, and an administrator deactivating a compromised
-- account had no way to tell how long was left (WILDBO-AUTH-03). Identity calls
-- POST /internal/gateway/purge-auth-cache on those events.
--
-- Deleting the entry was not enough. A request that missed the cache asks
-- identity, identity checks its blacklist and then queries the database; a
-- logout landing in that window blacklisted the jti and purged an entry that
-- did not exist yet, and the request then stored identity's "allowed" in the
-- cache. Every later request with the revoked token was served from that entry
-- until the TTL ran out -- the intermittent E2E logout failure. Two shared
-- (all-worker) records close it:
--
--   * a revocation marker per jti (per cache key for tokens without one),
--     checked on every request, cache hit or not, and after every fresh
--     authorization, so no ordering of fill and purge lets a revoked token
--     through, and it holds even if identity later vouches for the token
--     (its blacklist failing open while Redis is down);
--   * a generation counter bumped by every purge: a decision that was in
--     flight across a purge is not kept, which is what protects a full flush
--     (user or key deactivated), where nothing names the token.
--
-- Both live in auth_revoked rather than auth_cache, so flushing the cache
-- does not wipe them.
local GENERATION_KEY = "generation"
local MAX_REVOCATION_TTL = 86400

local function auth_generation()
    local state = ngx.shared.auth_revoked
    return state and state:get(GENERATION_KEY) or 0
end

local function bump_auth_generation()
    local state = ngx.shared.auth_revoked
    if state then
        state:incr(GENERATION_KEY, 1, 0)
    end
end

-- The name a token is revoked under: its jti when it is a JWT that carries
-- one (so identity can revoke a session it holds no raw token for), otherwise
-- its cache key.
local function revocation_id(token, token_type, cache_key)
    if token_type == "bearer" then
        local jti = utils.jwt_jti(token)
        if jti then
            return "jti:" .. jti
        end
    end
    return "key:" .. cache_key
end

local function is_revoked(rid)
    local state = ngx.shared.auth_revoked
    return state ~= nil and rid ~= nil and state:get(rid) ~= nil
end

local function flush_auth_cache()
    local auth_cache = ngx.shared.auth_cache
    if not auth_cache then return false end
    auth_cache:flush_all()
    auth_cache:flush_expired()
    return true
end

-- Record revocation markers. Returns how many were stored.
--
-- safe_set never evicts another live entry, so neither the generation counter
-- nor an earlier marker can be pushed out. If the dict is full the marker
-- cannot be kept; the whole auth cache is flushed instead, so no cached
-- decision survives and the next request goes to identity, whose blacklist
-- refuses the token. The revocation is still effective, only without the
-- defense in depth, and it is still reported as done.
local function store_markers(rids, ttl, cache_ttl)
    local state = ngx.shared.auth_revoked
    if not state then
        flush_auth_cache()
        return #rids
    end
    ttl = math.min(math.max(tonumber(ttl) or MAX_REVOCATION_TTL, cache_ttl), MAX_REVOCATION_TTL)
    local flushed = false
    for _, rid in ipairs(rids) do
        local ok, err = state:safe_set(rid, true, ttl)
        if not ok and not flushed then
            utils.log("warn", "Revocation marker not stored; flushing the auth cache", {error = err})
            flush_auth_cache()
            flushed = true
        end
    end
    return #rids
end

local function configured_cache_ttl()
    local config = get_config()
    return (config and config.cache_ttl) or CACHE_TTL
end

-- Revoke JWTs by jti. `ttl` should be the tokens' remaining lifetime; it is
-- raised to the cache TTL, so a marker always outlives any decision cached
-- before it, and capped at a day.
function _M.revoke_jtis(jtis, ttl)
    bump_auth_generation()
    local rids = {}
    for _, jti in ipairs(jtis) do
        rids[#rids + 1] = "jti:" .. jti
    end
    return store_markers(rids, ttl, configured_cache_ttl())
end

-- Revoke one token given in full (the purge older identity versions send).
function _M.purge_cache_entry(token, token_type, ttl)
    bump_auth_generation()
    token_type = token_type or "bearer"
    local cache_key = utils.generate_auth_cache_key(token, token_type)
    store_markers({revocation_id(token, token_type, cache_key)}, ttl, configured_cache_ttl())
    local auth_cache = ngx.shared.auth_cache
    if auth_cache then
        auth_cache:delete(cache_key)
    end
    return true
end

function _M.purge_all_cache()
    bump_auth_generation()
    return flush_auth_cache()
end

-- Sessions issued before a password change (#569).
--
-- A password change must end the account's other sessions, and identity
-- does not keep the jtis it issued. It records instead, per user, the time
-- up to which tokens are no longer valid (users.tokens_valid_after), and
-- sends the same cutoff here before it commits the change. The gateway
-- keeps it as a marker "user:<id>" = cutoff, in auth_revoked like the jti
-- markers, and refuses a bearer token of that user whose iat is not later,
-- on a cache hit and after a fresh authorization alike: a decision cached
-- before the change, or one in flight across it, is not served. Tokens
-- issued after the change (the new one identity hands the session that
-- changed the password, or a new login) carry a later iat and pass. API
-- keys are not sessions and are not affected.
local function user_cutoff_key(user_id)
    return "user:" .. tostring(user_id)
end

local function predates_password_change(token, token_type, auth_data)
    if token_type ~= "bearer" or not auth_data or not auth_data.user_id then
        return false
    end
    local state = ngx.shared.auth_revoked
    local cutoff = state and state:get(user_cutoff_key(auth_data.user_id))
    if type(cutoff) ~= "number" then
        return false
    end
    -- A token without an iat cannot show that it is newer than the cutoff.
    local iat = utils.jwt_iat(token)
    return iat == nil or iat <= cutoff
end

-- Record per-user cutoffs: `users` is a list of {user_id, not_before}.
-- Returns how many were stored. Unlike a jti marker, a cutoff that cannot
-- be kept is reported as not stored -- flushing the cache would not cover
-- the time until identity commits the change -- so identity refuses to
-- change the password rather than leave the other sessions open.
function _M.revoke_user_sessions(users, ttl)
    bump_auth_generation()
    local state = ngx.shared.auth_revoked
    if not state then
        return 0
    end
    ttl = math.min(
        math.max(tonumber(ttl) or MAX_REVOCATION_TTL, configured_cache_ttl()),
        MAX_REVOCATION_TTL
    )
    local stored = 0
    for _, entry in ipairs(users) do
        local key = user_cutoff_key(entry.user_id)
        local cutoff = entry.not_before
        -- Two changes close together: keep the later cutoff.
        local current = state:get(key)
        if type(current) == "number" and current > cutoff then
            cutoff = current
        end
        local ok, err = state:safe_set(key, cutoff, ttl)
        if ok then
            stored = stored + 1
        else
            utils.log("warn", "Password-change cutoff not stored", {error = err})
        end
    end
    return stored
end

-- API keys (#593).
--
-- Revoking a key only set it inactive in identity's database, and the
-- decision cached here for it went on being served for up to the cache TTL:
-- a key revoked because it leaked kept working for five minutes. Identity
-- does not keep the raw key, so it cannot name the cache key derived from
-- it; it names the key by its id instead, which it also reports on every
-- authorization it grants for the key (auth_data.api_key_id). The gateway
-- keeps a marker "apikey:<id>" in auth_revoked and refuses a decision for
-- that key on a cache hit and after a fresh authorization alike, like the
-- jti markers above. Identity sends the marker before it commits the
-- revocation, and every other change that disables keys (a user
-- deactivated or deleted, a member removed from the team) does the same.
local function api_key_marker(api_key_id)
    return "apikey:" .. api_key_id
end

local function names_api_key(auth_data)
    local id = auth_data and auth_data.api_key_id
    return type(id) == "string" and id ~= ""
end

-- Whether a decision for an API key may not be served. A decision that does
-- not name its key cannot be checked against a revocation, so it is not
-- served either: identity names the key on every authorization it grants.
local function api_key_revoked(token_type, auth_data)
    if token_type ~= "api_key" then
        return false
    end
    if not names_api_key(auth_data) then
        return true
    end
    return is_revoked(api_key_marker(auth_data.api_key_id))
end

-- Record API-key revocation markers. Returns how many were stored. As for
-- password-change cutoffs, a marker that cannot be kept is reported as not
-- stored -- flushing the cache would not cover the time until identity
-- commits the revocation -- so identity answers 503 and revokes nothing.
function _M.revoke_api_keys(api_key_ids, ttl)
    bump_auth_generation()
    local state = ngx.shared.auth_revoked
    if not state then
        return 0
    end
    ttl = math.min(
        math.max(tonumber(ttl) or MAX_REVOCATION_TTL, configured_cache_ttl()),
        MAX_REVOCATION_TTL
    )
    local stored = 0
    for _, api_key_id in ipairs(api_key_ids) do
        local ok, err = state:safe_set(api_key_marker(api_key_id), true, ttl)
        if ok then
            stored = stored + 1
        else
            utils.log("warn", "API-key revocation marker not stored", {error = err})
        end
    end
    return stored
end

-- Team memberships (#613).
--
-- Removing a member from a team revokes their API keys for the team (#593),
-- but a session is not bound to a team: identity resolves the team on every
-- authorization (the oldest membership), and the gateway caches the answer.
-- The removed member's sessions went on being served "allowed for team T"
-- for up to the cache TTL. Identity now sends, before it commits the
-- removal, a marker "member:<user id>:<team id>" = the instant of the
-- removal, and the gateway refuses a session decision for that user in that
-- team when the token was issued up to that instant, on a cache hit and
-- after a fresh authorization alike -- the same comparison as the
-- password-change cutoff, but for one team only. The user's sessions keep
-- working in their other teams: the refused decision is dropped from the
-- cache, and the next request is authorized afresh, by which time identity
-- no longer resolves the team they left. Tokens issued after the removal
-- (a new login, should the user be added back) carry a later iat and pass.
local function membership_marker(user_id, team_id)
    return "member:" .. tostring(user_id) .. ":" .. tostring(team_id)
end

local function removed_from_team(token, token_type, auth_data)
    if token_type ~= "bearer" or not auth_data
            or not auth_data.user_id or not auth_data.team_id then
        return false
    end
    local state = ngx.shared.auth_revoked
    local cutoff = state and state:get(membership_marker(auth_data.user_id, auth_data.team_id))
    if type(cutoff) ~= "number" then
        return false
    end
    -- A token without an iat cannot show that it is newer than the removal.
    local iat = utils.jwt_iat(token)
    return iat == nil or iat <= cutoff
end

-- Record membership markers: `memberships` is a list of {user_id, team_id,
-- not_before}. Returns how many were stored. As for the other markers
-- identity sends before it commits, one that cannot be kept is reported as
-- not stored, and identity answers 503 and removes nobody.
function _M.revoke_team_sessions(memberships, ttl)
    bump_auth_generation()
    local state = ngx.shared.auth_revoked
    if not state then
        return 0
    end
    ttl = math.min(
        math.max(tonumber(ttl) or MAX_REVOCATION_TTL, configured_cache_ttl()),
        MAX_REVOCATION_TTL
    )
    local stored = 0
    for _, entry in ipairs(memberships) do
        local key = membership_marker(entry.user_id, entry.team_id)
        local cutoff = entry.not_before
        -- Two removals close together: keep the later cutoff.
        local current = state:get(key)
        if type(current) == "number" and current > cutoff then
            cutoff = current
        end
        local ok, err = state:safe_set(key, cutoff, ttl)
        if ok then
            stored = stored + 1
        else
            utils.log("warn", "Team-membership marker not stored", {error = err})
        end
    end
    return stored
end

-- A session that has left the team is refused with 403, not 401: the
-- token is still valid, and the dashboard must not end the session over
-- it. The next request is authorized afresh and lands in the team the user
-- still belongs to, if any.
local function refuse_left_team(auth_data)
    utils.log("info", "Refused a session in a team its user was removed from", {
        user_id = auth_data.user_id,
        team_id = auth_data.team_id
    })
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "application/json"
    ngx.say(utils.json_encode({
        error = "team_membership_ended",
        message = "The account no longer belongs to this team"
    }))
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- Whether the credential behind a decision has expired: identity reports
-- when an API key (or a session token) stops being valid, and a decision is
-- not served past that, whatever is left of its cache TTL (#593).
local function credential_expired(auth_data)
    local expires = auth_data and auth_data.credential_expires_at
    return type(expires) == "number" and expires <= ngx.now()
end

local function refuse_revoked()
    utils.log("info", "Refused a revoked token")
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header.content_type = "application/json"
    ngx.say(utils.json_encode({
        error = "invalid_token",
        message = "Authentication token is invalid or expired"
    }))
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local function refuse_pending_password_change(auth_data)
    if not auth_data or auth_data.password_change_required ~= true then
        return
    end
    utils.log("info", "Refused a session that must change its password", {
        user_id = auth_data.user_id
    })
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "application/json"
    ngx.say(utils.json_encode({
        error = "PASSWORD_CHANGE_REQUIRED",
        message = "Change the initial password before using the account"
    }))
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- Set authentication data in cache with proper TTL
local function set_cached_auth_data(cache_key, auth_data, config)
    local auth_cache = ngx.shared.auth_cache
    local ttl = config.cache_ttl or CACHE_TTL

    -- Never past the credential's own expiry (#593): an API key that
    -- expires in ten seconds was cached, and served, for the full TTL.
    local credential_expires = auth_data.credential_expires_at
    if type(credential_expires) == "number" then
        local remaining = credential_expires - ngx.now()
        if remaining <= 0 then
            return
        end
        ttl = math.min(ttl, remaining)
    end

    -- Set expiration time
    auth_data.expires_at = ngx.now() + ttl
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
    -- Fixed-window counter, O(1) per request.
    --
    -- This used to keep every request timestamp in the window as a JSON list:
    -- each request decoded the list, filtered it, appended, re-encoded and wrote
    -- it back, so per-request cost grew with the request rate and total work over
    -- a window was quadratic in it. The component deciding whether to shed load
    -- was therefore most expensive exactly when the system was busiest
    -- (WILDBO-SCAL-04). A counter per fixed window is how nginx's own limit_req
    -- works, and it lets the shared dict expire the key itself.
    local team_id = auth_data.team_id
    local limit_per_hour = RATE_LIMIT_PER_HOUR
    local window_size = 60                       -- seconds
    local max_requests = math.max(1, math.floor(limit_per_hour * window_size / 3600))

    local rate_cache = ngx.shared.rate_limit_cache
    local now = ngx.time()
    local window = math.floor(now / window_size)
    local key = "rate:" .. team_id .. ":" .. window
    local reset_at = (window + 1) * window_size

    -- incr with an init value creates the key when absent; the TTL is set once
    -- so the entry disappears with its window and nothing has to prune.
    local count, err = rate_cache:incr(key, 1, 0, window_size * 2)
    if not count then
        -- A full shared dict must not take the gateway down: log and allow.
        utils.log("warn", "Rate limit counter unavailable, allowing request", {error = err})
        return
    end

    -- Limit and Remaining must describe the same budget.
    --
    -- Limit reported the hourly figure (10000) while Remaining counted against
    -- the 60-second window actually enforced (166), so a client reading both
    -- saw "10000 allowed, 163 left" and could not compute a backoff from it.
    -- Limit is now the window that is enforced; the hourly policy it derives
    -- from is stated separately, in the form RFC 9239 uses.
    ngx.header["X-RateLimit-Limit"] = tostring(max_requests)
    ngx.header["X-RateLimit-Remaining"] = tostring(math.max(0, max_requests - count))
    ngx.header["X-RateLimit-Reset"] = tostring(reset_at)
    ngx.header["X-RateLimit-Policy"] = tostring(limit_per_hour) .. ";w=3600"

    if count > max_requests then
        utils.log("warn", "Rate limit exceeded", {
            team_id = team_id,
            current_requests = count,
            limit = max_requests,
            window_size = window_size
        })

        ngx.status = ngx.HTTP_TOO_MANY_REQUESTS
        ngx.header.content_type = "application/json"
        ngx.header["Retry-After"] = tostring(reset_at - now)

        ngx.say(utils.json_encode({
            error = "rate_limit_exceeded",
            message = "Rate limit exceeded",
            limit_per_hour = limit_per_hour,
            retry_after_seconds = reset_at - now
        }))
        ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
    end
end

-- The API-key scope each authenticated route requires (#647).
--
-- One row per route the gateway authenticates, first match wins. A row
-- covers its path and everything under it -- "/api/v1/tools" and
-- "/api/v1/tools/..." alike -- unless it is `exact`. The patterns this
-- replaces each spelled the prefix out, and the ones written with a trailing
-- slash missed the collection itself: GET /api/v1/tools, the list of tools,
-- fell through to the generic "read", so a tools:read key was refused there
-- and a data key holding "read" could list the tools.
--
-- `read` is required for GET, HEAD and OPTIONS, `delete` for DELETE where
-- the row names one, `write` for every other method.
--
-- A path with no row requires "admin" (UNMAPPED_ROUTE_SCOPE): a route added
-- to the configuration without a row here is closed to scope-limited keys
-- rather than opened to whoever holds a generic "read" or "write". The
-- harness (test/route_scope_tests.sh) pins the scope of every location that
-- authenticates and fails for one it has no pin for.
local ROUTE_SCOPES = {
    -- Security tools, AI agents and the asynchronous tool tasks (#567):
    -- reading and listing is tools:read, running or cancelling tools:execute.
    { path = "/api/v1/tools", read = "tools:read", write = "tools:execute" },
    { path = "/api/v1/agents", read = "tools:read", write = "tools:execute" },
    { path = "/api/v1/tasks", read = "tools:read", write = "tools:execute" },
    -- No row for /api/v1/automations: the gateway does not route to n8n
    -- any more (#714), and no route requires tools:admin, which a key may
    -- still hold and which satisfies tools:read and tools:execute.
    -- Guardian: vulnerability, asset and compliance data.
    { path = "/api/v1/guardian", read = "data:read", write = "data:write", delete = "data:delete" },
    -- Sensor telemetry ingest (#628): its own scope, so that a sensor's key
    -- can be limited to sending telemetry. data:ingest satisfies nothing
    -- else, and "write" and "data:write" keep satisfying this route. Exact:
    -- nothing under it is the ingest route.
    { path = "/api/v1/data/ingest", exact = true, read = "read", write = "data:ingest" },
    -- The data, CSPM and responder services, and identity's health probe:
    -- generic read and write.
    { path = "/api/v1/data", read = "read", write = "write" },
    { path = "/api/v1/cspm", read = "read", write = "write" },
    { path = "/api/v1/responder", read = "read", write = "write" },
    { path = "/api/v1/identity/health", exact = true, read = "read", write = "write" },
}

local UNMAPPED_ROUTE_SCOPE = "admin"

local function route_covers(route, uri)
    if uri == route.path then
        return true
    end
    return not route.exact and uri:sub(1, #route.path + 1) == route.path .. "/"
end

-- Map a request (path + method) to the API-key scope it requires.
local function required_scope_for_request(uri, method)
    if type(uri) ~= "string" then
        return UNMAPPED_ROUTE_SCOPE
    end
    for _, route in ipairs(ROUTE_SCOPES) do
        if route_covers(route, uri) then
            if method == "GET" or method == "HEAD" or method == "OPTIONS" then
                return route.read
            end
            if method == "DELETE" and route.delete then
                return route.delete
            end
            return route.write
        end
    end
    return UNMAPPED_ROUTE_SCOPE
end

-- The path a request is mapped by: the one nginx chose the location for.
--
-- ngx.var.uri is not that path once the location has rewritten it, and
-- rewrite directives run before access_by_lua. The automations location
-- stripped its prefix that way, so the map saw "/rest/workflows" instead of
-- "/api/v1/automations/rest/workflows": it required the generic "read" or
-- "write" where tools:admin was meant, and mapped whatever followed the
-- prefix as a path of its own. That location is gone (#714); a location
-- that rewrites is still mapped by the path it was chosen for, not by the
-- one it rewrites to. The server block copies $uri into
-- $wildbox_route_uri before any location runs; a configuration that does
-- not declare it leaves every path unmapped, which fails closed.
local function route_uri()
    local uri = ngx.var.wildbox_route_uri
    if type(uri) == "string" and uri ~= "" then
        return uri
    end
    return nil
end

-- Does the set of granted scopes satisfy the required one?
-- Hierarchy: "admin" > "write" > "read"; "<res>:admin" > "<res>:write|execute"
-- > "<res>:read"; generic scopes satisfy resource scopes of equal-or-lower level.
local function scopes_satisfy(granted, required)
    local set = {}
    for _, s in ipairs(granted) do set[s] = true end

    if set[required] then return true end
    if set["admin"] then return true end  -- global admin satisfies everything
    -- "*" is the explicit unrestricted marker. Legacy keys used to carry NULL
    -- scopes, which meant unrestricted-by-absence; alembic revision
    -- f5a6b7c8d9e0 migrates those to ["*"] so the privileged state is a value
    -- that was written rather than one inferred from a missing column
    -- (WILDBO-DOM-07). Without this branch those migrated keys would be denied.
    if set["*"] then return true end

    local res, action = required:match("^(.-):(.+)$")
    if not res then
        -- Generic scope (read|write).
        if required == "read" then
            return (set["read"] or set["write"]) == true
        elseif required == "write" then
            return set["write"] == true
        end
        return false
    end

    -- Resource-scoped requirement. Resource admin satisfies any action.
    if set[res .. ":admin"] then return true end
    if action == "read" then
        return (set[res .. ":read"] or set[res .. ":write"] or set[res .. ":execute"]
                or set["read"] or set["write"]) == true
    elseif action == "write" or action == "execute" then
        return (set[res .. ":write"] or set[res .. ":execute"] or set["write"]) == true
    elseif action == "ingest" then
        -- Granted explicitly, or by a write scope on the resource (or a
        -- generic one): a key that could write data could ingest before.
        return (set[res .. ":ingest"] or set[res .. ":write"] or set["write"]) == true
    elseif action == "delete" then
        return set[res .. ":delete"] == true  -- needs explicit delete (or res admin, above)
    end
    return false
end

-- Enforce API-key scopes. No-op for interactive/JWT auth and legacy keys, whose
-- scopes are null (cjson.null / not a table) → unrestricted.
local function enforce_scopes(auth_data)
    local scopes = auth_data.scopes
    if type(scopes) ~= "table" then
        return  -- unrestricted (bearer/JWT, or legacy key without scopes)
    end

    local uri = route_uri()
    local required = required_scope_for_request(uri, ngx.var.request_method)
    if scopes_satisfy(scopes, required) then
        return
    end

    utils.log("warn", "API key missing required scope", {
        required = required,
        path = uri or ngx.var.uri,
        method = ngx.var.request_method
    })
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "application/json"
    ngx.say(utils.json_encode({
        error = "insufficient_scope",
        message = "This API key is not authorized for this operation.",
        required_scope = required
    }))
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- What the credential is and what it may do, for the service (#637).
--
-- The gateway enforced an API key's scopes and then forwarded the user, the
-- team and the role alone: a service could not tell a sensor's data:ingest
-- key from its owner's session, so the scope map above was the only check
-- there was, and a mistake in it had nothing behind it. The service now
-- gets what the decision was made on, and checks it again where it matters
-- (open-security-shared: scopes.py, gateway_auth.require_scope):
--
--   X-Wildbox-Auth-Type  "api_key" for an API key, "session" for a login
--                        session (a JWT). Always sent.
--   X-Wildbox-Scopes     the key's scopes, separated by single spaces. "*"
--                        for a key that is not limited (identity reports no
--                        scope list for it). Not sent for a session, which
--                        has no scopes and is not limited by them.
--
-- Both are the gateway's to say: clean_request_headers() removes a client's
-- own, and proxy_params.conf sends them from variables that only this
-- function fills in, so a location that does not authenticate forwards
-- neither.
local AUTH_TYPE_SESSION = "session"
local AUTH_TYPE_API_KEY = "api_key"
local UNRESTRICTED_SCOPE = "*"

-- A scope as identity grants them: "*", a name, or name:action. Anything
-- else is not forwarded: the services refuse a list they cannot read, and
-- a scope that is no scope satisfied nothing here either.
local function forwardable_scope(scope)
    if type(scope) ~= "string" then
        return false
    end
    return scope == UNRESTRICTED_SCOPE
        or scope:match("^[a-z][a-z0-9_-]*$") ~= nil
        or scope:match("^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$") ~= nil
end

-- The auth type and the scopes header ("" for none) of a decision.
local function credential_headers(auth_data, token_type)
    -- By what identity answered as well as by the header the credential
    -- came in: a decision that names an API key is one.
    local auth_type = AUTH_TYPE_SESSION
    if token_type == "api_key" or names_api_key(auth_data) then
        auth_type = AUTH_TYPE_API_KEY
    end

    local scopes = auth_data.scopes
    if type(scopes) ~= "table" then
        -- Not limited by scopes (see enforce_scopes). For a key that is a
        -- privilege, and it is written out rather than left to be inferred
        -- from a missing header.
        if auth_type == AUTH_TYPE_API_KEY then
            return auth_type, UNRESTRICTED_SCOPE
        end
        return auth_type, ""
    end

    local forwarded = {}
    for _, scope in ipairs(scopes) do
        if forwardable_scope(scope) then
            forwarded[#forwarded + 1] = scope
        else
            utils.log("warn", "Scope not forwarded: not a scope name", {
                user_id = auth_data.user_id
            })
        end
    end
    return auth_type, table.concat(forwarded, " ")
end

-- Set authentication headers for backend services
local function set_auth_headers(auth_data, config, token_type)
    -- SECURITY: Strip ALL client-supplied auth headers BEFORE setting validated ones.
    -- This prevents identity spoofing via forged X-Wildbox-* headers.
    utils.clean_request_headers()

    ngx.var.wildbox_user_id = auth_data.user_id or ""
    ngx.var.wildbox_team_id = auth_data.team_id or ""
    ngx.var.wildbox_role = auth_data.role or "user"
    -- The proof of origin, for this request only: proxy_params.conf sends
    -- it from this variable, which stays empty on the locations that do not
    -- authenticate, so the gateway vouches only for callers it knows (#664).
    ngx.var.wildbox_gateway_secret = config.gateway_secret or ""

    -- Set headers for backend services (from validated auth_data only)
    ngx.req.set_header("X-Wildbox-User-ID", auth_data.user_id)
    ngx.req.set_header("X-Wildbox-Team-ID", auth_data.team_id)
    ngx.req.set_header("X-Wildbox-Role", auth_data.role)

    -- The credential (#637). An empty $wildbox_scopes sends no header.
    local auth_type, scopes = credential_headers(auth_data, token_type)
    ngx.var.wildbox_auth_type = auth_type
    ngx.var.wildbox_scopes = scopes
    ngx.req.set_header("X-Wildbox-Auth-Type", auth_type)
    if scopes ~= "" then
        ngx.req.set_header("X-Wildbox-Scopes", scopes)
    end

    -- Response headers for client
    ngx.header["X-Wildbox-Team-ID"] = auth_data.team_id
end

-- The gateway could not get an authorization decision. That is transient
-- by nature, so say so the way HTTP does: a JSON body like every other
-- refusal here, and Retry-After. The generic branch used to exit with no
-- body at all, which nginx filled with its HTML error page (#609).
local function service_unavailable(retry_after)
    ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
    ngx.header.content_type = "application/json"
    ngx.header["Retry-After"] = tostring(math.max(1, math.ceil(tonumber(retry_after) or 1)))
    ngx.say(utils.json_encode({
        error = "service_unavailable",
        message = "Authentication service temporarily unavailable"
    }))
    ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
end

-- Main authentication handler.
--
-- Only for a location whose upstream is a Wildbox service: a request let
-- through is sent on with X-Gateway-Secret and the caller's identity, which
-- such a service checks and trusts. Whoever else holds the secret can state
-- any user, team and role to every service, so nothing that is not Wildbox's
-- may sit behind a location that calls this. n8n did (#711), and is not
-- routed to any more (#714); tests/scripts and the harness
-- (test/upstream_header_tests.sh) fail for a location that proxies anywhere
-- else.
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

    -- Token length validation: reject suspiciously long tokens
    if #token > 4096 then
        utils.log("warn", "Token exceeds maximum length", {length = #token})
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.header.content_type = "application/json"
        ngx.say(utils.json_encode({
            error = "invalid_token",
            message = "Authentication token exceeds maximum allowed length"
        }))
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    -- Generate cache key
    local cache_key = utils.generate_auth_cache_key(token, token_type)

    -- Try to get auth data from cache first
    local auth_data, cache_err = get_cached_auth_data(cache_key)

    -- A decision cached before the gateway knew about API-key revocation
    -- (#593) does not name its key, or one cached for a credential that has
    -- since expired: ask identity again rather than serve it.
    if auth_data and ((token_type == "api_key" and not names_api_key(auth_data))
                      or credential_expired(auth_data)) then
        ngx.shared.auth_cache:delete(cache_key)
        auth_data, cache_err = nil, "cache_miss"
    end

    -- A cache hit is only as good as the revocation markers allow (#571).
    -- Entries cached before the marker existed carry no revocation_id.
    if auth_data and is_revoked(auth_data.revocation_id
                                or revocation_id(token, token_type, cache_key)) then
        ngx.shared.auth_cache:delete(cache_key)
        refuse_revoked()
    end
    -- Nor may it outlive a password change of its user (#569).
    if auth_data and predates_password_change(token, token_type, auth_data) then
        ngx.shared.auth_cache:delete(cache_key)
        refuse_revoked()
    end
    -- Nor the revocation of its API key (#593).
    if auth_data and api_key_revoked(token_type, auth_data) then
        ngx.shared.auth_cache:delete(cache_key)
        refuse_revoked()
    end
    -- Nor the removal of its user from its team (#613).
    if auth_data and removed_from_team(token, token_type, auth_data) then
        ngx.shared.auth_cache:delete(cache_key)
        refuse_left_team(auth_data)
    end

    -- If not in cache, validate with identity service
    if cache_err == "cache_miss" then
        -- Read before asking identity: if a purge lands while the answer is
        -- in flight, the answer is not kept (see bump_auth_generation).
        local generation = auth_generation()
        local rid = revocation_id(token, token_type, cache_key)

        local validation_err, retry_after
        auth_data, validation_err, retry_after = validate_token_with_identity(token, token_type, config)

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
                service_unavailable(retry_after)
            else
                utils.log("error", "Authentication service error", {error = validation_err})
                service_unavailable(1)
            end
        end

        -- Identity may have answered before a logout that has since been
        -- recorded here.
        if is_revoked(rid) then
            refuse_revoked()
        end
        if predates_password_change(token, token_type, auth_data) then
            refuse_revoked()
        end
        -- Or before the revocation of its API key, which identity sends
        -- here before it commits it (#593).
        if api_key_revoked(token_type, auth_data) then
            refuse_revoked()
        end
        -- Or before the removal of its user from the team it resolved,
        -- which identity likewise sends here before it commits (#613).
        if removed_from_team(token, token_type, auth_data) then
            refuse_left_team(auth_data)
        end

        -- Cache the validation result, then drop it again if a purge ran
        -- meanwhile. The order matters against a purge running in another
        -- worker: it bumps the generation before writing its marker, so
        -- either the check below sees the bump, or the marker is written
        -- after this entry and every hit on it is refused above.
        auth_data.revocation_id = rid
        set_cached_auth_data(cache_key, auth_data, config)
        if auth_generation() ~= generation then
            ngx.shared.auth_cache:delete(cache_key)
        end
    end

    -- An account a team admin created must change its initial password
    -- before it can use any service (#573). identity says so on every
    -- authorization, and the decision is cached with it, so this holds on a
    -- cache hit too. The routes that change the password, read the account
    -- and log out are identity's own and do not come through here.
    refuse_pending_password_change(auth_data)

    -- Enforce API-key least-privilege scopes (no-op for interactive/JWT auth)
    enforce_scopes(auth_data)

    -- Apply rate limiting
    apply_rate_limiting(auth_data)

    -- Set authentication headers for backend services
    set_auth_headers(auth_data, config, token_type)

    local request_time = (ngx.now() - request_start) * 1000
    utils.log("debug", "Authorization completed", {
        user_id = auth_data.user_id,
        team_id = auth_data.team_id,
        cache_hit = auth_data.cache_hit,
        duration_ms = request_time
    })
end

return _M
