"""check_gateway_config.py: the nginx variables authenticate() assigns (#637).

auth_handler.set_auth_headers() stores the caller's identity, the proof of
origin and, since #637, the credential's type and scopes in nginx variables,
and proxy_params.conf sends them to the service. Assigning a variable the
configuration does not declare is an error at request time: every
authenticated request answers 500. The check fails for a configuration that
calls authenticate() without declaring each of them empty.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_gateway_config.py"
GATEWAY_DIR = ROOT / "open-security-gateway" / "nginx"

spec = importlib.util.spec_from_file_location("check_gateway_config_assigned", SCRIPT)
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


def write_gateway(tmp_path, site):
    gateway = tmp_path / "nginx"
    (gateway / "conf.d").mkdir(parents=True)
    (gateway / "nginx.conf").write_text("env A;\n")
    (gateway / "conf.d" / "site.conf").write_text(site)
    return gateway


def server_declaring(names, route_uri=True):
    declarations = "".join(f'    set ${name} "";\n' for name in names)
    # The path the scope map reads (#647), where the check asks for it.
    if route_uri:
        declarations += "    set $wildbox_route_uri $uri;\n"
    return "server {\n" + declarations + _AUTH_LOCATION + "}\n"


def test_both_gateway_configurations_declare_what_authenticate_assigns():
    for name in ("conf.d/wildbox_gateway.conf", "test/wildbox_gateway_test.conf"):
        assert (
            cgc.undeclared_assigned_variables(GATEWAY_DIR / name, GATEWAY_DIR) == []
        ), name


def test_the_list_is_what_the_handler_assigns():
    handler = (GATEWAY_DIR / "lua" / "auth_handler.lua").read_text()

    assert {"wildbox_auth_type", "wildbox_scopes"} <= set(cgc.ASSIGNED_VARIABLES)
    for name in cgc.ASSIGNED_VARIABLES:
        assert f"ngx.var.{name} =" in handler, name


def test_the_credential_variables_are_what_proxy_params_sends():
    proxy_params = (GATEWAY_DIR / "includes" / "proxy_params.conf").read_text()

    assert "proxy_set_header X-Wildbox-Auth-Type $wildbox_auth_type;" in proxy_params
    assert "proxy_set_header X-Wildbox-Scopes $wildbox_scopes;" in proxy_params


def test_authenticating_with_every_variable_declared_passes(tmp_path):
    gateway = write_gateway(tmp_path, server_declaring(cgc.ASSIGNED_VARIABLES))

    assert cgc.check(gateway) == []


def test_each_missing_credential_variable_is_a_failure(tmp_path):
    for missing in ("wildbox_auth_type", "wildbox_scopes"):
        declared = [name for name in cgc.ASSIGNED_VARIABLES if name != missing]
        gateway = write_gateway(tmp_path / missing, server_declaring(declared))

        failures = cgc.check(gateway)

        assert len(failures) == 1, failures
        assert f"${missing}" in failures[0] and "conf.d/site.conf" in failures[0]


def test_a_commented_declaration_does_not_count(tmp_path):
    site = server_declaring(cgc.ASSIGNED_VARIABLES).replace(
        '    set $wildbox_scopes "";', '    # set $wildbox_scopes "";'
    )
    gateway = write_gateway(tmp_path, site)

    failures = cgc.check(gateway)

    assert len(failures) == 1 and "$wildbox_scopes" in failures[0]


def test_a_variable_seeded_with_a_value_does_not_count(tmp_path):
    """Declared empty: what a location that authenticates nobody forwards."""
    site = server_declaring(cgc.ASSIGNED_VARIABLES).replace(
        '    set $wildbox_auth_type "";', '    set $wildbox_auth_type "session";'
    )
    gateway = write_gateway(tmp_path, site)

    failures = cgc.check(gateway)

    assert len(failures) == 1 and "$wildbox_auth_type" in failures[0]


def test_a_configuration_that_does_not_authenticate_declares_nothing(tmp_path):
    gateway = write_gateway(
        tmp_path, "location = /internal/purge {\n    return 204;\n}\n"
    )

    assert cgc.check(gateway) == []
