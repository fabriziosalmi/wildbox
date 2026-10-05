-- Wildbox Gateway CORS: which origins may call the API from a browser (#712).
--
-- The dashboard is normally served by this gateway, on the API's own
-- origin, and needs none of this. Two documented setups do: a dashboard
-- served from another origin (NEXT_PUBLIC_GATEWAY_URL) and the dashboard's
-- local development server on http://localhost:3000. For those a browser
-- asks first (a preflight: OPTIONS with Origin and
-- Access-Control-Request-Method) and then reads only responses that name
-- its origin.
--
-- It did not work. The server block answered 405 to every OPTIONS request
-- before any location ran, so no preflight was ever answered; the allowlist
-- was a map written into nginx.conf (localhost only), not CORS_ORIGINS, the
-- setting the deployment guide tells operators to list their origins in;
-- only identity's routes carried the headers; and the configuration the
-- harness ran had no such 405, so its CORS cases passed.
--
-- CORS is decided here, in one place, for every API route and for the
-- production and the test configuration alike (includes/cors.conf):
--
--   * the allowlist is CORS_ORIGINS: exact origins, comma-separated (or a
--     JSON list, the other form identity accepts). Nothing is allowed that
--     is not listed; "*" is refused, because these are credentialed
--     requests, for which a wildcard is not valid and would not be safe;
--   * a preflight from a listed origin is answered 204 by the gateway,
--     before authentication (a preflight carries no credentials) and
--     without reaching a service. Every other OPTIONS request is 405, as
--     before;
--   * every response to a request from a listed origin names that origin
--     and allows credentials, the gateway's own refusals included (a page
--     cannot read a 401 that does not name it). A response to any other
--     origin names nobody, whatever the service behind said: its own CORS
--     headers are removed, so the gateway is the one authority and no
--     header is ever doubled;
--   * every API response carries Vary: Origin.
--
-- The dashboard's own pages are not labelled: only the API is.

local cjson = require "cjson.safe"

local _M = {}

-- What a preflight is told. The methods are the ones the server block
-- accepts; the request headers are the ones a client of the API sets.
local ALLOW_METHODS = "GET, HEAD, POST, PUT, PATCH, DELETE"
local ALLOW_HEADERS = "Accept, Authorization, Cache-Control, Content-Type, "
    .. "If-Modified-Since, X-API-Key, X-Requested-With"
-- What a page may read besides the body: the rate limit and the request id.
local EXPOSE_HEADERS = "Retry-After, X-Request-ID, X-RateLimit-Limit, "
    .. "X-RateLimit-Remaining, X-RateLimit-Reset, X-RateLimit-Policy"
-- How long a browser may reuse a preflight's answer, in seconds.
local MAX_AGE = "7200"

local ALLOWED_METHODS = {
    GET = true, HEAD = true, POST = true, PUT = true, DELETE = true, PATCH = true,
}

-- The paths that are the API: everything under /api/, and identity's
-- routes under /auth/. The rest of /auth/ and everything else is the
-- dashboard.
local API_PREFIXES = {
    "/api/",
    "/auth/users/",
    "/auth/jwt/",
    "/auth/register",
    "/auth/forgot-password",
    "/auth/reset-password",
}

local function is_api_path(uri, method)
    if type(uri) ~= "string" then
        return false
    end
    for _, prefix in ipairs(API_PREFIXES) do
        if uri:sub(1, #prefix) == prefix then
            return true
        end
    end
    -- POST /auth/logout is identity's; GET /auth/logout is a page.
    return uri == "/auth/logout" and method ~= "GET" and method ~= "HEAD"
end

-- One origin as a browser sends it: scheme, host, optional port. No path,
-- no wildcard, no "null". Returned in lower case, or nil.
local function normalize_origin(value)
    if type(value) ~= "string" then
        return nil
    end
    local origin = value:lower()
    local host = origin:match("^https?://([a-z0-9.-]+)$")
        or origin:match("^https?://([a-z0-9.-]+):%d%d?%d?%d?%d?$")
    if host and not host:match("^[.-]") and not host:match("[.-]$") and not host:find("..", 1, true) then
        return origin
    end
    -- An IPv6 literal.
    if origin:match("^https?://%[[0-9a-f:]+%]$") or origin:match("^https?://%[[0-9a-f:]+%]:%d%d?%d?%d?%d?$") then
        return origin
    end
    return nil
end

-- CORS_ORIGINS as a set of origins. Unset or empty allows nobody. Set, every
-- entry must be an origin: anything else is refused, and with it the
-- configuration (the module is loaded by init_by_lua, where an error stops
-- nginx from starting), rather than dropped without a word and found out
-- when a browser is refused, or read as more than was meant.
function _M.parse_origins(raw)
    local origins = {}
    if raw == nil or raw:match("^%s*$") then
        return origins
    end
    local entries = {}
    if raw:match("^%s*%[") then
        local decoded = cjson.decode(raw)
        local keys = 0
        if type(decoded) == "table" then
            for _ in pairs(decoded) do
                keys = keys + 1
            end
        end
        if type(decoded) ~= "table" or keys ~= #decoded then
            return nil, "CORS_ORIGINS starts like a JSON list and is not a list of origins"
        end
        for index = 1, #decoded do
            entries[index] = decoded[index]
        end
    else
        for entry in raw:gmatch("[^,]+") do
            local trimmed = entry:match("^%s*(.-)%s*$")
            if trimmed ~= "" then
                entries[#entries + 1] = trimmed
            end
        end
    end
    for _, entry in ipairs(entries) do
        local origin = normalize_origin(entry)
        if not origin then
            return nil, string.format(
                "CORS_ORIGINS must list origins such as https://dashboard.example.com "
                .. "(scheme, host and optional port; no path, no wildcard), got %q",
                string.sub(tostring(entry), 1, 80))
        end
        origins[origin] = true
    end
    return origins
end

-- Read where the module is loaded: init_by_lua, in the master process, like
-- RATE_LIMIT_PER_HOUR in auth_handler (#627). CORS_ORIGINS is declared with
-- `env` in nginx.conf.
local ORIGINS, ORIGINS_ERROR = _M.parse_origins(os.getenv("CORS_ORIGINS"))
if not ORIGINS then
    error(ORIGINS_ERROR, 0)
end

-- The method the request is about: for a preflight, the one it asks for.
local function effective_method()
    local method = ngx.var.request_method
    if method == "OPTIONS" then
        local asked = ngx.var.http_access_control_request_method
        if asked and asked ~= "" then
            return asked
        end
    end
    return method
end

-- The path the client asked for. A location may have rewritten $uri by the
-- time a response is labelled; the server block keeps the original in
-- $wildbox_route_uri (#647), which is still empty while the server block's
-- own directives run, when $uri is the original anyway.
local function request_path()
    local path = ngx.var.wildbox_route_uri
    if type(path) ~= "string" or path == "" then
        path = ngx.var.uri
    end
    return path
end

-- The request's origin when it is listed and the request is for the API,
-- else "". includes/cors.conf keeps it in $cors_allow_origin.
function _M.allowed_origin()
    local origin = ngx.var.http_origin
    if type(origin) ~= "string" or origin == "" then
        return ""
    end
    if not is_api_path(request_path(), effective_method()) then
        return ""
    end
    if ORIGINS[origin:lower()] then
        return origin
    end
    return ""
end

-- What the server block does with the request before any location runs:
--   ""           an accepted method: go on
--   "preflight"  a CORS preflight from a listed origin: answer 204
--   "refused"    any other method, any other OPTIONS: answer 405
-- includes/cors.conf keeps it in $cors_request.
function _M.request_kind()
    local method = ngx.var.request_method
    if ALLOWED_METHODS[method] then
        return ""
    end
    if method == "OPTIONS"
            and ngx.var.http_access_control_request_method
            and ngx.var.http_access_control_request_method ~= ""
            and _M.allowed_origin() ~= "" then
        return "preflight"
    end
    return "refused"
end

local CORS_RESPONSE_HEADERS = {
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
}

local function vary_on_origin()
    local vary = ngx.header["Vary"]
    if vary == nil then
        ngx.header["Vary"] = "Origin"
        return
    end
    local values = type(vary) == "table" and vary or { vary }
    for _, value in ipairs(values) do
        for field in tostring(value):gmatch("[^,%s]+") do
            if field:lower() == "origin" or field == "*" then
                return
            end
        end
    end
    values[#values + 1] = "Origin"
    ngx.header["Vary"] = table.concat(values, ", ")
end

-- Label a response (header_filter_by_lua, includes/cors.conf).
function _M.label_response()
    local preflight = ngx.var.cors_request == "preflight"
    if not is_api_path(request_path(), effective_method()) then
        return
    end

    -- The one authority: whatever the service behind said about CORS goes.
    for _, name in ipairs(CORS_RESPONSE_HEADERS) do
        ngx.header[name] = nil
    end
    vary_on_origin()

    local origin = ngx.var.cors_allow_origin
    if type(origin) ~= "string" or origin == "" then
        return
    end
    -- The specific origin, never "*": the request carries credentials.
    ngx.header["Access-Control-Allow-Origin"] = origin
    ngx.header["Access-Control-Allow-Credentials"] = "true"
    if preflight then
        ngx.header["Access-Control-Allow-Methods"] = ALLOW_METHODS
        ngx.header["Access-Control-Allow-Headers"] = ALLOW_HEADERS
        ngx.header["Access-Control-Max-Age"] = MAX_AGE
    else
        ngx.header["Access-Control-Expose-Headers"] = EXPOSE_HEADERS
    end
end

return _M
