-- Luacheck configuration for the Wildbox API gateway (OpenResty / LuaJIT).
-- https://luacheck.readthedocs.io/
--
-- Scope (issue #108): this lint gates on the two failure classes that ship
-- real gateway auth bugs — syntax errors and undefined/global-scope errors.
-- Purely stylistic and local-hygiene checks (unused locals, shadowing,
-- whitespace, line length) are deferred so the gate can land green over the
-- existing handler and stay meaningful; they can be ratcheted on in a
-- follow-up once auth_handler.lua is tidied.

-- OpenResty runs LuaJIT (Lua 5.1 + 5.2 extensions); luacheck's builtin
-- "ngx_lua" std is LuaJIT plus the OpenResty globals with the correct
-- mutability (a bare read_globals "ngx" flags every legitimate
-- ngx.status/ngx.header/ngx.var assignment as W122 setting-read-only-field).
std = "ngx_lua"

-- ndk (nginx devel kit) is not part of the ngx_lua std.
read_globals = {
    "ndk",
}

-- Keep: 0xx (syntax, always fatal) and 1xx (global-scope errors).
-- Defer: 2xx unused vars, 3xx unused values, 4xx shadowing,
--        5xx control-flow, 6xx whitespace/formatting.
ignore = {
    "2..",
    "3..",
    "4..",
    "5..",
    "6..",
}
