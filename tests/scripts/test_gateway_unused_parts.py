"""The gateway holds nothing that nothing uses (#776).

Three things did. The production image installed gettext, unzip, make, gcc
and musl-dev, "build tools and luarocks" for a luarocks that was never
installed: the container that faces the network shipped a compiler nobody
ran. Compose passed ``GATEWAY_DEBUG``, nginx.conf declared it with ``env``,
and ``auth_handler.lua`` read it into a ``debug_mode`` field no line of Lua
ever looked at, so an operator who set it changed nothing. And the two
server configurations set a ``$gateway_debug`` variable that only a function
with no caller read.

The Compose side of the second is
``test_compose_variables_are_read.py``'s: it fails for a variable Compose
passes that no code reads. What is checked here is what that test cannot
see, because a read is a read to it: that each package the image installs
has a user, that each script copied into the image is run, that every
variable nginx is told to keep is one the Lua reads, that each setting the
handler loads is one it uses, and that each variable a server block sets is
one something reads. The files are read as they are; nothing is built.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "open-security-gateway"
DOCKERFILE = GATEWAY / "Dockerfile"
ENTRYPOINT = GATEWAY / "scripts" / "docker-entrypoint.sh"
NGINX = GATEWAY / "nginx"
LUA = sorted((NGINX / "lua").glob("*.lua"))
SERVER_CONFS = (
    NGINX / "conf.d" / "wildbox_gateway.conf",
    NGINX / "test" / "wildbox_gateway_test.conf",
)

# Package the production image installs -> where it is used, and the text
# that shows it there. A package added to the Dockerfile needs a row, and a
# row needs the use it names.
PACKAGE_USERS = {
    "curl": (DOCKERFILE, r"^HEALTHCHECK [^\n]*\\\n\s*CMD curl "),
    "openssl": (ENTRYPOINT, r"^\s*openssl req "),
    "wget": (DOCKERFILE, r"&& wget -O \S+ https://"),
    # What wget checks the HTTPS download against.
    "ca-certificates": (DOCKERFILE, r"&& wget -O \S+ https://"),
}


def code(text, comment="#"):
    """A file without its comment lines."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith(comment)
    )


def installed_packages(dockerfile):
    """The packages of every ``apk add`` of a Dockerfile."""
    packages = set()
    joined = code(dockerfile).replace("\\\n", " ")
    for command in re.findall(r"apk add ([^\n&|;]*)", joined):
        packages |= {word for word in command.split() if not word.startswith("-")}
    return packages


# --- the image -------------------------------------------------------------------


def test_the_package_list_is_read():
    """The reader finds packages written the way the Dockerfile writes them."""
    sample = "RUN apk add --no-cache \\\n    curl \\\n    gcc\nRUN true\n"

    assert installed_packages(sample) == {"curl", "gcc"}
    assert installed_packages(DOCKERFILE.read_text())


def test_every_package_the_image_installs_has_a_user():
    packages = installed_packages(DOCKERFILE.read_text())

    assert packages - set(PACKAGE_USERS) == set(), (
        "installed by open-security-gateway/Dockerfile and used by nothing "
        "this test knows of"
    )
    for package in sorted(packages):
        path, use = PACKAGE_USERS[package]
        assert re.search(use, code(path.read_text()), re.M), (package, path.name)


def test_no_row_is_left_for_a_package_the_image_no_longer_installs():
    assert set(PACKAGE_USERS) == installed_packages(DOCKERFILE.read_text())


def test_every_script_copied_into_the_image_is_run():
    """The Dockerfile copies scripts/ whole: a file there ships."""
    dockerfile = code(DOCKERFILE.read_text())
    assert re.search(r"^COPY scripts/ /usr/local/bin/$", dockerfile, re.M)

    entrypoint = re.search(
        r'^ENTRYPOINT \["/usr/local/bin/([^"]+)"\]$', dockerfile, re.M
    )
    assert entrypoint, "the image has no entrypoint this test can read"
    run = {entrypoint.group(1)}
    run |= set(
        re.findall(r"^\s*/usr/local/bin/(\S+)", code(ENTRYPOINT.read_text()), re.M)
    )

    # .dockerignore keeps the editor's and the system's dot files out.
    shipped = {
        path.name
        for path in (GATEWAY / "scripts").iterdir()
        if not path.name.startswith(".")
    }
    assert shipped == run


# --- the environment -------------------------------------------------------------


def lua_reads():
    """Every name the gateway's Lua asks the environment for."""
    names = set()
    for path in LUA:
        names |= set(
            re.findall(r'os\.getenv\(\s*"(\w+)"\s*\)', code(path.read_text(), "--"))
        )
    for path in SERVER_CONFS:
        names |= set(re.findall(r'os\.getenv\(\s*"(\w+)"\s*\)', code(path.read_text())))
    return names


def test_every_variable_nginx_keeps_is_one_the_lua_reads():
    """``env NAME;`` keeps a variable for the workers; it reads nothing."""
    declared = set(
        re.findall(r"^env (\w+);$", code((NGINX / "nginx.conf").read_text()), re.M)
    )

    assert declared
    assert declared == lua_reads()


def test_every_setting_the_handler_loads_is_one_it_uses():
    """debug_mode was loaded from GATEWAY_DEBUG and read by nothing."""
    handler = code((NGINX / "lua" / "auth_handler.lua").read_text(), "--")
    loaded = set(re.findall(r"^\s*(\w+) = [^\n]*os\.getenv\(", handler, re.M))
    lua = "\n".join(code(path.read_text(), "--") for path in LUA)

    assert {"identity_service_url", "gateway_secret", "cache_ttl"} <= loaded
    for field in sorted(loaded):
        assert re.search(rf"\bconfig\.{field}\b", lua), field


# --- the variables of the server blocks ------------------------------------------


def test_every_variable_a_server_block_sets_is_read_somewhere():
    """A variable that is set and never read is a setting that looks alive.

    $gateway_debug was set to "false" in both files; with the function that
    read it gone (the next test), it would have been one.
    """
    includes = "\n".join(
        code(path.read_text()) for path in sorted((NGINX / "includes").glob("*.conf"))
    )
    lua = "\n".join(code(path.read_text(), "--") for path in LUA)

    for path in SERVER_CONFS:
        text = code(path.read_text())
        variables = set(re.findall(r"^\s*set(?:_by_lua_block)? \$(\w+)\b", text, re.M))
        assert variables, path.name
        for name in sorted(variables):
            uses = [
                # In nginx: anywhere but the directive that sets it.
                len(re.findall(rf"\${name}\b", text + "\n" + includes))
                - len(
                    re.findall(
                        rf"^\s*set(?:_by_lua_block)? \${name}\b",
                        text + "\n" + includes,
                        re.M,
                    )
                ),
                # In Lua, in the modules or in a block of a configuration
                # file: read, or assigned for a header nginx then sends.
                len(
                    re.findall(
                        rf"\bngx\.var\.{name}\b", "\n".join((lua, text, includes))
                    )
                ),
            ]
            assert sum(uses) > 0, (path.name, name)


def test_the_debug_headers_nothing_could_turn_on_are_gone():
    """utils.set_debug_headers read $gateway_debug and had no caller."""
    lua = "\n".join(code(path.read_text(), "--") for path in LUA)

    assert "set_debug_headers" not in lua
    assert "X-Debug-" not in lua


# --- the functions of the Lua modules (#788) -------------------------------------


def exported_functions(text):
    """The names a Lua module exports: ``function _M.name(`` and ``_M.name = function``."""
    return set(re.findall(r"^function _M\.(\w+)\s*\(", text, re.M)) | set(
        re.findall(r"^_M\.(\w+)\s*=\s*function\b", text, re.M)
    )


def test_the_exported_functions_are_read():
    """The reader finds a function written either way, and not a local one."""
    sample = (
        "local _M = {}\n"
        "local function helper() end\n"
        "function _M.first(a) end\n"
        "_M.second = function() end\n"
        "return _M\n"
    )

    assert exported_functions(sample) == {"first", "second"}
    for path in LUA:
        assert exported_functions(code(path.read_text(), "--")), path.name


def test_every_function_a_lua_module_exports_has_a_caller():
    """utils.validate_team_access compared a user and a team with the answer
    of identity, and nothing called it: authenticate() takes both from that
    answer. A function nothing calls is a check that looks made."""
    confs = sorted(NGINX.rglob("*.conf"))
    everything = "\n".join(
        [code(path.read_text(), "--") for path in LUA]
        + [code(path.read_text()) for path in confs]
    )

    for path in LUA:
        text = code(path.read_text(), "--")
        for name in sorted(exported_functions(text)):
            calls = re.findall(rf"[\w\]\)]\s*[.:]\s*{name}\s*\(", everything)
            # Its definition, written ``function _M.name(``, is one of them.
            definitions = re.findall(rf"^function _M\.{name}\s*\(", text, re.M)
            assert len(calls) > len(definitions), (path.name, name)


def test_validate_team_access_is_gone():
    lua = "\n".join(code(path.read_text(), "--") for path in LUA)

    assert "validate_team_access" not in lua


# --- the locations of the test configuration (#788) ------------------------------

HARNESS = GATEWAY / "test"


def locations_of(text):
    """The path of every location of an nginx file: the literal one of an
    exact or prefix location, the literal start of a regular expression."""
    paths = []
    for modifier, path in re.findall(
        r"^\s*location\s+(=|\^~|~\*?)?\s*(\S+)\s*\{", code(text), re.M
    ):
        if modifier.startswith("~"):
            path = re.match(r"\^?((?:/[\w.-]+)*/?)", path).group(1)
        paths.append(path)
    return paths


def test_the_locations_are_read():
    sample = (
        "location /health {\n"
        "    location = /api/v1/tasks {\n"
        "location ^~ /api/v1/tasks/ {\n"
        "location ~ ^/api/v1/agents/(.*)$ {\n"
        "# location /api/v1/sensor/ {\n"
    )

    assert locations_of(sample) == [
        "/health",
        "/api/v1/tasks",
        "/api/v1/tasks/",
        "/api/v1/agents/",
    ]


def test_every_location_of_the_test_configuration_is_called_by_the_harness():
    """/api/v1/auth/register was limited as production limits registration,
    and no script sent it a request: the location looked tested. A location
    of this file exists for a script that calls it."""
    scripts = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(HARNESS.iterdir())
        if path.suffix in (".sh", ".py", ".txt") and path.name != "mock_identity.py"
    )
    locations = locations_of(SERVER_CONFS[1].read_text())

    assert "/api/v1/auth/login" in locations  # the file was read
    for path in sorted(set(locations) - {"/"}):
        assert path in scripts, (
            f"wildbox_gateway_test.conf: no script of open-security-gateway/test "
            f"names {path}"
        )


def test_the_registration_route_nothing_called_is_gone():
    assert "/api/v1/auth/register" not in code(SERVER_CONFS[1].read_text())
