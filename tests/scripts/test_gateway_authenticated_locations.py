"""Tests for the gateway harness's list of authenticating locations (#647).

route_scope_tests.sh pins the API-key scope of every location that calls
authenticate() and reads the locations with authenticated_locations.py. The
list has to be right for the pins to mean anything: these check the reader
on small configurations and on the configuration that ships, and that the
harness pins each location it finds there.
"""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "open-security-gateway"
SCRIPT = GATEWAY / "test" / "authenticated_locations.py"
HARNESS = GATEWAY / "test" / "route_scope_tests.sh"
PRODUCTION_CONF = GATEWAY / "nginx" / "conf.d" / "wildbox_gateway.conf"

spec = importlib.util.spec_from_file_location("authenticated_locations", SCRIPT)
al = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = al
spec.loader.exec_module(al)

AUTH = (
    "        access_by_lua_block {\n"
    '            local auth_handler = require "auth_handler"\n'
    "            auth_handler.authenticate()\n"
    "        }\n"
)


def server(*blocks):
    return "server {\n" + "".join(blocks) + "}\n"


def location(spec_text, body):
    return f"    location {spec_text} {{\n{body}    }}\n"


def test_every_kind_of_location_is_read_as_written():
    conf = server(
        location("= /api/v1/tools", AUTH),
        location("~ ^/api/v1/tools/(.*)$", AUTH),
        location("^~ /api/v1/tasks/", AUTH),
        location("/api/v1/data/", AUTH),
    )

    assert al.authenticated_locations(conf) == [
        "= /api/v1/tools",
        "~ ^/api/v1/tools/(.*)$",
        "^~ /api/v1/tasks/",
        "/api/v1/data/",
    ]


def test_a_location_that_does_not_authenticate_is_left_out():
    conf = server(
        location("/api/v1/identity/", "        proxy_pass http://identity;\n"),
        location("/api/v1/data/", AUTH),
    )

    assert al.authenticated_locations(conf) == ["/api/v1/data/"]


def test_a_commented_out_location_is_left_out():
    conf = server(
        "    # location /api/v1/sensor/ {\n"
        "    #     access_by_lua_block {\n"
        "    #         auth_handler.authenticate()\n"
        "    #     }\n"
        "    # }\n",
        location("/api/v1/data/", AUTH),
    )

    assert al.authenticated_locations(conf) == ["/api/v1/data/"]


def test_a_commented_out_call_does_not_authenticate():
    body = (
        "        # auth_handler.authenticate()\n"
        "        access_by_lua_block {\n"
        "            -- auth_handler.authenticate()\n"
        "            ngx.exit(403)\n"
        "        }\n"
    )

    assert al.authenticated_locations(server(location("/api/v1/x/", body))) == []


def test_lua_tables_and_json_bodies_do_not_end_the_block():
    body = (
        "        access_by_lua_block {\n"
        "            local options = { retry = { times = 2 } }\n"
        '            require("auth_handler").authenticate()\n'
        "        }\n"
        "        error_page 404 = @missing;\n"
    )
    conf = server(
        location("/api/", '        return 404 \'{"error":"endpoint_not_found"}\';\n'),
        location("/api/v1/data/", body),
        location("/api/v1/cspm/", AUTH),
    )

    assert al.authenticated_locations(conf) == ["/api/v1/data/", "/api/v1/cspm/"]


def test_an_unbalanced_configuration_is_an_error():
    conf = "server {\n    location /api/v1/data/ {\n" + AUTH

    with pytest.raises(ValueError):
        al.authenticated_locations(conf)


def test_the_production_configuration_is_read():
    text = PRODUCTION_CONF.read_text()
    locations = al.authenticated_locations(text)

    assert "= /api/v1/tools" in locations
    assert "~ ^/api/v1/tools/(.*)$" in locations
    assert "/api/v1/automations/" in locations
    # The identity passthrough and the dashboard do not authenticate here.
    assert "/api/v1/identity/" not in locations
    assert "/" not in locations
    # The sensor route is commented out.
    assert not any("sensor" in entry for entry in locations)
    # As many as the configuration has calls outside comments.
    calls = sum(
        1
        for line in text.splitlines()
        if "auth_handler.authenticate()" in al.strip_comment(line)
    )
    assert len(locations) == calls


def test_the_harness_pins_every_production_location():
    """Checked on the wire by the harness; here so that it also fails early."""
    pinned = set(re.findall(r"^pin '([^']+)'", HARNESS.read_text(), re.MULTILINE))
    locations = set(al.authenticated_locations(PRODUCTION_CONF.read_text()))

    assert locations - pinned == set(), "locations without a pinned scope"
    assert pinned - locations == set(), "pins for locations that do not exist"


def test_the_command_prints_one_location_a_line(capsys):
    assert al.main([str(PRODUCTION_CONF)]) == 0
    printed = capsys.readouterr().out.splitlines()

    assert printed == al.authenticated_locations(PRODUCTION_CONF.read_text())
    assert al.main([]) == 2
