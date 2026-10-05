"""Tests for check_gateway_config.py, the guard on the gateway's env declarations.

RATE_LIMIT_PER_HOUR was read by the gateway's Lua with os.getenv but never
declared with `env` in nginx.conf, and nginx hands its workers only the
declared variables (#627). These run the check on the repository's own
gateway configuration and on small configurations written in each test.
"""

import importlib.util
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_gateway_config.py"
GATEWAY_DIR = ROOT / "open-security-gateway" / "nginx"

spec = importlib.util.spec_from_file_location("check_gateway_config", SCRIPT)
cgc = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cgc
spec.loader.exec_module(cgc)


def write_gateway(tmp_path, nginx_conf, files):
    gateway = tmp_path / "nginx"
    gateway.mkdir()
    (gateway / "nginx.conf").write_text(nginx_conf)
    for name, text in files.items():
        path = gateway / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return gateway


def test_the_repository_gateway_declares_every_variable_it_reads():
    assert cgc.check(GATEWAY_DIR) == []


def test_the_rate_limit_is_declared():
    assert "RATE_LIMIT_PER_HOUR" in cgc.declared_variables(GATEWAY_DIR / "nginx.conf")


def test_removing_a_declaration_fails(tmp_path):
    copy = tmp_path / "nginx"
    shutil.copytree(GATEWAY_DIR, copy)
    conf = copy / "nginx.conf"
    conf.write_text(
        "\n".join(
            line
            for line in conf.read_text().splitlines()
            if line.strip() != "env RATE_LIMIT_PER_HOUR;"
        )
    )

    failures = cgc.check(copy)

    assert len(failures) == 1
    assert "RATE_LIMIT_PER_HOUR" in failures[0]
    assert "auth_handler.lua" in failures[0]


def test_a_read_in_a_conf_lua_block_is_checked(tmp_path):
    gateway = write_gateway(
        tmp_path,
        "env A;\n",
        {"conf.d/site.conf": 'set_by_lua_block $x { return os.getenv("B") or "" }\n'},
    )

    failures = cgc.check(gateway)

    assert len(failures) == 1
    assert "reads B" in failures[0]
    assert "site.conf:1" in failures[0]


def test_declarations_with_a_value_and_single_quotes_count(tmp_path):
    gateway = write_gateway(
        tmp_path,
        "env A=1;\nenv B;\n",
        {"lua/m.lua": "local a = os.getenv('A')\nlocal b = os.getenv( \"B\" )\n"},
    )

    assert cgc.check(gateway) == []


def test_comments_are_not_reads(tmp_path):
    gateway = write_gateway(
        tmp_path,
        '# os.getenv("NGINX_COMMENT")\nenv A;\n',
        {
            "lua/m.lua": '-- os.getenv("LUA_COMMENT")\nlocal a = os.getenv("A") -- os.getenv("TAIL")\n',
            "includes/x.conf": '    # os.getenv("CONF_COMMENT")\n',
        },
    )

    assert cgc.check(gateway) == []


def test_a_name_that_is_not_a_literal_fails(tmp_path):
    gateway = write_gateway(
        tmp_path,
        "env A;\n",
        {"lua/m.lua": 'local name = "A"\nlocal a = os.getenv(name)\n'},
    )

    failures = cgc.check(gateway)

    assert len(failures) == 1
    assert "not a string literal" in failures[0]
    assert "m.lua:2" in failures[0]


def test_main_exit_status(tmp_path, capsys):
    good = write_gateway(tmp_path, "env A;\n", {"lua/m.lua": 'os.getenv("A")\n'})
    assert cgc.main(["--gateway-dir", str(good)]) == 0

    (good / "lua" / "m.lua").write_text('os.getenv("MISSING")\n')
    assert cgc.main(["--gateway-dir", str(good)]) == 1
    assert "MISSING" in capsys.readouterr().out


# The agents route authenticated with its own inline Lua, which called
# identity's /internal/authorize directly and so skipped everything
# auth_handler does (#630).
def test_a_location_calling_identity_authorization_itself_fails(tmp_path):
    gateway = write_gateway(
        tmp_path,
        "env A;\n",
        {
            "conf.d/site.conf": (
                "location ~ ^/api/v1/agents/(.*)$ {\n"
                "    access_by_lua_block {\n"
                '        httpc:request_uri("http://identity:8001/internal/authorize", {})\n'
                "    }\n"
                "}\n"
            )
        },
    )

    failures = cgc.check(gateway)

    assert len(failures) == 1
    assert "site.conf:3" in failures[0]
    assert "auth_handler.authenticate()" in failures[0]


def test_a_comment_naming_identity_authorization_is_not_a_call(tmp_path):
    gateway = write_gateway(
        tmp_path,
        "env A;\n",
        {"conf.d/site.conf": "# auth_handler calls /internal/authorize\n"},
    )

    assert cgc.check(gateway) == []


def test_the_lua_module_may_call_identity_authorization(tmp_path):
    gateway = write_gateway(
        tmp_path,
        "env A;\n",
        {"lua/auth_handler.lua": 'local url = base .. "/internal/authorize"\n'},
    )

    assert cgc.check(gateway) == []


def test_the_agents_routes_authenticate_through_auth_handler():
    conf = (GATEWAY_DIR / "conf.d" / "wildbox_gateway.conf").read_text()
    for opening, upstream in (
        (
            "location ~ ^/api/v1/agents/(.*)$ {",
            "proxy_pass http://agents_service/v1/$1$is_args$args;",
        ),
        (
            "location = /api/v1/agents/stats {",
            "proxy_pass http://agents_service/stats;",
        ),
    ):
        start = conf.index(opening)
        block = conf[start : conf.index("\n    }\n", start)]

        assert "auth_handler.authenticate()" in block, opening
        assert upstream in block, opening


# --- The path the scope map reads (#647) -----------------------------------

_AUTHENTICATING_LOCATION = (
    "location /api/v1/x/ {\n"
    "    access_by_lua_block {\n"
    '        local auth_handler = require "auth_handler"\n'
    "        auth_handler.authenticate()\n"
    "    }\n"
    "}\n"
)


def _site(declaration):
    # The variables authenticate() assigns (#637), so that the route URI is
    # the one thing each case varies.
    assigned = "".join(f'    set ${name} "";\n' for name in cgc.ASSIGNED_VARIABLES)
    # And the one CORS policy (#712).
    assigned += "    include /etc/nginx/includes/cors.conf;\n"
    return {
        "conf.d/site.conf": "server {\n"
        + assigned
        + declaration
        + _AUTHENTICATING_LOCATION
        + "}\n"
    }


def test_both_gateway_configurations_declare_the_route_uri():
    for name in ("conf.d/wildbox_gateway.conf", "test/wildbox_gateway_test.conf"):
        assert cgc.missing_route_uri(GATEWAY_DIR / name, GATEWAY_DIR) == [], name


def test_authenticating_without_the_route_uri_fails(tmp_path):
    gateway = write_gateway(tmp_path, "env A;\n", _site(""))

    failures = cgc.check(gateway)

    assert len(failures) == 1
    assert "conf.d/site.conf" in failures[0]
    assert "$wildbox_route_uri" in failures[0]


def test_a_commented_route_uri_declaration_does_not_count(tmp_path):
    gateway = write_gateway(
        tmp_path, "env A;\n", _site("    # set $wildbox_route_uri $uri;\n")
    )

    assert len(cgc.check(gateway)) == 1


def test_the_route_uri_must_be_the_request_path(tmp_path):
    gateway = write_gateway(
        tmp_path, "env A;\n", _site('    set $wildbox_route_uri "";\n')
    )

    assert len(cgc.check(gateway)) == 1


def test_authenticating_with_the_route_uri_passes(tmp_path):
    gateway = write_gateway(
        tmp_path, "env A;\n", _site("    set $wildbox_route_uri $uri;\n")
    )

    assert cgc.check(gateway) == []


def test_a_configuration_that_does_not_authenticate_needs_no_route_uri(tmp_path):
    gateway = write_gateway(
        tmp_path,
        "env A;\n",
        {"includes/purge.conf": "location = /internal/purge {\n    return 204;\n}\n"},
    )

    assert cgc.check(gateway) == []
