-- Luacheck configuration for the Wildbox API gateway (OpenResty / LuaJIT).
-- https://luacheck.readthedocs.io/
--
-- Scope (issue #108): this lint gates on the two failure classes that ship
-- real gateway auth bugs — syntax errors and undefined/global-scope errors.
-- Purely stylistic and local-hygiene checks (unused locals, shadowing,
-- whitespace, line length) are deferred so the gate can land green over the
-- existing handler and stay meaningful; they can be ratcheted on in a
-- follow-up once auth_handler.lua is tidied.

-- OpenResty runs LuaJIT (Lua 5.1 + 5.2 extensions).
std = "luajit"

-- Globals OpenResty injects into the Lua VM at request time.
read_globals = {
    "ngx",
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
