"""check_gateway_config.py: CORS is decided in one place (#712).

The production configuration answered 405 to every OPTIONS request before
any location ran, so no CORS preflight was ever answered, while the test
configuration the harness ran had no such rule and passed its CORS cases.
Both now include one file, includes/cors.conf, whose rules are in
lua/cors.lua. The check fails for a configuration that authenticates
without the include, and for one that sets an Access-Control-* header by
itself.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_gateway_config.py"
GATEWAY_DIR = ROOT / "open-security-gateway" / "nginx"

spec = importlib.util.spec_from_file_location("check_gateway_config_cors", SCRIPT)
cgc = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cgc
spec.loader.exec_module(cgc)

_AUTH_LOCATION = (
    "location /api/v1/x/ {\n"
    "    access_by_lua_block {\n"
    '        local auth_handler = require "auth_handler"\n'
    "        auth_handler.authenticate()\n"
    "    }\n"
    "}\n"
)
_INCLUDE = "    include /etc/nginx/includes/cors.conf;\n"


def write_gateway(tmp_path, site, name="conf.d/site.conf"):
    gateway = tmp_path / "nginx"
    path = gateway / name
    path.parent.mkdir(parents=True)
    (gateway / "nginx.conf").write_text("env A;\n")
    path.write_text(site)
    return gateway


def server(*extra):
    declarations = "".join(f'    set ${name} "";\n' for name in cgc.ASSIGNED_VARIABLES)
    declarations += "    set $wildbox_route_uri $uri;\n"
    return "server {\n" + declarations + "".join(extra) + _AUTH_LOCATION + "}\n"


def test_both_gateway_configurations_include_the_one_policy():
    for name in ("conf.d/wildbox_gateway.conf", "test/wildbox_gateway_test.conf"):
        assert cgc.cors_outside_the_include(GATEWAY_DIR / name, GATEWAY_DIR) == [], name


def test_the_repository_gateway_passes_the_whole_check():
    assert cgc.check(GATEWAY_DIR) == []


def test_the_include_is_what_refuses_methods_and_answers_preflights():
    """What the two configurations share is the rule that went missing in one."""
    include = (GATEWAY_DIR / "includes" / "cors.conf").read_text()
    production = (GATEWAY_DIR / "conf.d" / "wildbox_gateway.conf").read_text()

    assert "if ($cors_request = refused)" in include and "return 405" in include
    assert "if ($cors_request = preflight)" in include and "return 204" in include
    assert 'require("cors").label_response()' in include
    # The production configuration no longer has a method rule of its own.
    assert "$request_method !~" not in production
    # And the allowlist is the setting, read by the module nginx.conf loads.
    nginx_conf = (GATEWAY_DIR / "nginx.conf").read_text()
    assert "env CORS_ORIGINS;" in nginx_conf and 'require "cors"' in nginx_conf
    assert "cors_allow_origin" not in nginx_conf
    assert 'os.getenv("CORS_ORIGINS")' in (GATEWAY_DIR / "lua" / "cors.lua").read_text()


def test_compose_passes_the_setting_to_the_gateway():
    base = (ROOT / "docker-compose.yml").read_text()
    overlay = (ROOT / "docker-compose.prod.yml").read_text()

    gateway = base[base.index("\n  gateway:\n") :]
    gateway = gateway[: gateway.index("\n  ", gateway.index("networks:"))]
    assert "- CORS_ORIGINS=${CORS_ORIGINS:-http://localhost:3000}" in gateway

    production = overlay[overlay.index("\n  gateway:\n") :]
    production = production[: production.index("\n  dashboard:")]
    assert "- CORS_ORIGINS=${CORS_ORIGINS}" in production


def test_authenticating_with_the_include_passes(tmp_path):
    gateway = write_gateway(tmp_path, server(_INCLUDE))

    assert cgc.check(gateway) == []


def test_authenticating_without_the_include_fails(tmp_path):
    gateway = write_gateway(tmp_path, server())

    failures = cgc.check(gateway)

    assert len(failures) == 1, failures
    assert "cors.conf" in failures[0] and "conf.d/site.conf" in failures[0]


def test_a_commented_include_does_not_count(tmp_path):
    gateway = write_gateway(
        tmp_path, server("    # include /etc/nginx/includes/cors.conf;\n")
    )

    assert len(cgc.check(gateway)) == 1


def test_a_location_that_sets_a_cors_header_itself_fails(tmp_path):
    site = server(
        _INCLUDE,
        "    location /api/v1/y/ {\n"
        "        add_header 'Access-Control-Allow-Origin' '*' always;\n"
        "        return 204;\n"
        "    }\n",
    )
    gateway = write_gateway(tmp_path, site)

    failures = cgc.check(gateway)

    assert len(failures) == 1, failures
    assert "Access-Control-" in failures[0] and "site.conf:" in failures[0]


def test_an_include_file_that_sets_a_cors_header_fails(tmp_path):
    """The file this check was written against, cors_params.conf."""
    gateway = write_gateway(
        tmp_path,
        "add_header 'Access-Control-Allow-Origin' $cors_allow_origin always;\n",
        name="includes/cors_params.conf",
    )

    failures = cgc.check(gateway)

    assert len(failures) == 1 and "includes/cors_params.conf:1" in failures[0]


def test_a_comment_about_cors_headers_is_not_one(tmp_path):
    site = server(
        _INCLUDE, "    # add_header 'Access-Control-Allow-Origin' was here once.\n"
    )
    gateway = write_gateway(tmp_path, site)

    assert cgc.check(gateway) == []


def test_a_configuration_that_does_not_authenticate_needs_no_include(tmp_path):
    gateway = write_gateway(
        tmp_path,
        "location = /internal/purge {\n    return 204;\n}\n",
        name="includes/purge.conf",
    )

    assert cgc.check(gateway) == []
