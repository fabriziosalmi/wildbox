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
        if "auth_handler.authenticate(" in al.strip_comment(line)
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


# --- The locations that proxy (#711) ----------------------------------------

UPSTREAM_HARNESS = GATEWAY / "test" / "upstream_header_tests.sh"


def test_a_location_that_proxies_is_listed_whether_it_authenticates_or_not():
    conf = server(
        location(
            "/api/v1/data/", AUTH + "        proxy_pass http://data_service/api/v1/;\n"
        ),
        location("/", "        proxy_pass http://dashboard_service;\n"),
        location("/api/", '        return 404 \'{"error":"endpoint_not_found"}\';\n'),
        location("/health", "        return 200 'ok';\n"),
    )

    assert al.proxying_locations(conf) == ["/api/v1/data/", "/"]


def test_a_commented_out_proxy_pass_does_not_proxy():
    conf = server(
        location(
            "/api/v1/sensor/",
            "        # proxy_pass http://sensor_service/api/v1/;\n        return 404;\n",
        ),
        "    # The original content was a proxy_pass to the legacy service.\n",
    )

    assert al.proxying_locations(conf) == []


def test_the_production_configuration_proxies_where_it_says():
    text = PRODUCTION_CONF.read_text()
    proxying = al.proxying_locations(text)

    # One location for each proxy_pass directive outside comments.
    directives = sum(
        1
        for line in text.splitlines()
        if al.strip_comment(line).lstrip().startswith("proxy_pass ")
    )
    assert len(proxying) == directives
    assert (
        "/" in proxying
        and "/api/v1/automations/" in proxying
        and "/api/v1/identity/" in proxying
    )
    # Every location that authenticates proxies somewhere.
    assert set(al.authenticated_locations(text)) <= set(proxying)
    # The catch-all and the health checks answer by themselves.
    assert "/api/" not in proxying and "/health" not in proxying


def test_the_harness_classifies_every_proxying_location():
    """Checked on the wire by the harness; here so that it also fails early."""
    harness = UPSTREAM_HARNESS.read_text()
    classified = set(re.findall(r"^upstream '([^']+)'", harness, re.MULTILINE))
    locations = set(al.proxying_locations(PRODUCTION_CONF.read_text()))

    assert (
        locations - classified == set()
    ), "proxying locations without a classification"
    assert (
        classified - locations == set()
    ), "classifications for locations that do not exist"


def test_only_wildbox_services_are_classified_as_backends():
    """A backend is sent the gateway's secret: the upstream must be one that checks it."""
    text = PRODUCTION_CONF.read_text()
    harness = UPSTREAM_HARNESS.read_text()
    kinds = dict(
        re.findall(
            r"^upstream '([^']+)'\s*\\?\s*(backend|identity|dashboard|third_party)\b",
            harness,
            re.MULTILINE,
        )
    )
    assert set(kinds) == set(al.proxying_locations(text))
    blocks = {}
    current = None
    for raw in text.splitlines():
        line = al.strip_comment(raw)
        match = re.match(r"^\s*location\s+(.+?)\s*\{\s*$", line)
        if match:
            current = match.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)

    wildbox_services = (
        "identity_service",
        "data_service",
        "cspm_service",
        "guardian_service",
        "responder_service",
        "agents_service",
        "api_service",
    )
    for spec, kind in kinds.items():
        body = "\n".join(blocks[spec])
        target = re.search(r"proxy_pass\s+http://([^/;\s]+)", body).group(1)
        if kind == "backend":
            assert (
                target in wildbox_services
            ), f"{spec} is a backend but proxies to {target}"
            assert "upstream = " not in body, spec
        if target not in wildbox_services and target != "dashboard_service":
            # Not a Wildbox service: it must be authenticated as a third party.
            assert kind == "third_party", f"{spec} proxies to {target}"
            assert 'authenticate({ upstream = "third_party" })' in body, spec


def test_the_command_lists_proxying_locations(capsys):
    assert al.main(["--proxying", str(PRODUCTION_CONF)]) == 0
    printed = capsys.readouterr().out.splitlines()

    assert printed == al.proxying_locations(PRODUCTION_CONF.read_text())
    assert al.main(["--proxying"]) == 2
