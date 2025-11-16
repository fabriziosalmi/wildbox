-- Wrapper script for API key authentication
-- Uses simplified auth handler that doesn't require shared dicts

local f, err = loadfile("/etc/nginx/lua/auth_apikey_simple.lua")
if not f then
    ngx.log(ngx.ERR, "Failed to load auth_apikey_simple.lua: ", err)
    ngx.exit(500)
end

f()
