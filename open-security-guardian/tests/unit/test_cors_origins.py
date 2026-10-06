"""guardian's allowed origins come from the variable Compose passes (#665).

``docker-compose.prod.yml`` passed ``CORS_ALLOWED_ORIGINS=${CORS_ORIGINS}`` to
guardian, whose list of origins was written in its settings: the operator's
origin was never allowed, and the development ones always were.

Under that overlay the variable holds the value the gateway reads as
``CORS_ORIGINS``. guardian reads it by the gateway's grammar: a value the
gateway starts on does not stop guardian, and the two allow the same origins.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import Client
from guardian.cors import DEVELOPMENT_ORIGINS, VARIABLE, allowed_origins

GUARDIAN_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = GUARDIAN_DIR.parent
PROD_OVERLAY = REPO_ROOT / "docker-compose.prod.yml"
GATEWAY_START_UP_TESTS = (
    REPO_ROOT / "open-security-gateway" / "test" / "startup_config_tests.sh"
)
GATEWAY_PARSER = REPO_ROOT / "open-security-gateway" / "nginx" / "lua" / "cors.lua"

# The values open-security-gateway/test/startup_config_tests.sh starts a
# gateway with: these it refuses...
GATEWAY_REFUSES = [
    "*",
    "https://*.example.com",
    "dashboard.example.com",
    "https://dashboard.example.com/",
    "https://dashboard.example.com/app",
    "https://a.example.com https://b.example.com",
    "null",
    "ftp://dashboard.example.com",
    '["https://a.example.com", 5]',
    '{"origin": "https://a.example.com"}',
    "https://a.example.com,*",
]
# ...and on these it starts, allowing the origins beside each.
GATEWAY_ACCEPTS = {
    "": [],
    "https://dashboard.example.com": ["https://dashboard.example.com"],
    "https://a.example.com, http://localhost:3000,": [
        "https://a.example.com",
        "http://localhost:3000",
    ],
    '["https://a.example.com", "http://localhost:3000"]': [
        "https://a.example.com",
        "http://localhost:3000",
    ],
    "http://[::1]:3000": ["http://[::1]:3000"],
    "HTTPS://Dashboard.Example.com:8443": ["https://dashboard.example.com:8443"],
}

# --- the variable ------------------------------------------------------------


def test_unset_means_the_development_origins():
    assert allowed_origins(None) == list(DEVELOPMENT_ORIGINS)
    assert "http://localhost:3000" in DEVELOPMENT_ORIGINS


@pytest.mark.parametrize("value", ["", "  ", ",", " , "])
def test_set_and_empty_means_none(value):
    assert allowed_origins(value) == []


def test_a_list_is_read():
    value = "https://dashboard.example.com, http://10.0.0.5:3000"

    assert allowed_origins(value) == [
        "https://dashboard.example.com",
        "http://10.0.0.5:3000",
    ]


def test_the_development_origins_are_not_added_to_a_list():
    assert allowed_origins("https://dashboard.example.com") == [
        "https://dashboard.example.com"
    ]


def test_a_repeat_is_dropped_and_case_is_not_kept():
    value = "https://dashboard.example.com,HTTPS://Dashboard.Example.COM"

    assert allowed_origins(value) == ["https://dashboard.example.com"]


# --- the JSON form, which the gateway and identity accept too ------------------


def test_a_json_list_of_one_origin_is_read():
    assert allowed_origins('["https://dashboard.example.com"]') == [
        "https://dashboard.example.com"
    ]


def test_a_json_list_of_several_origins_is_read():
    value = json.dumps(["https://a.example.com", "http://10.0.0.5:3000"])

    assert allowed_origins(value) == ["https://a.example.com", "http://10.0.0.5:3000"]
    assert allowed_origins(f"  {value}  ") == allowed_origins(value)


@pytest.mark.parametrize("value", ["[]", " [ ] ", "[\n]"])
def test_an_empty_json_list_means_none(value):
    assert allowed_origins(value) == []


@pytest.mark.parametrize(
    "value, entry",
    [
        ('["https://ok.example.com", "*"]', "'*'"),
        (
            '["https://ok.example.com", "dashboard.example.com"]',
            "'dashboard.example.com'",
        ),
        ('["https://dashboard.example.com/"]', "'https://dashboard.example.com/'"),
        ('["https://ok.example.com", 5]', "'5'"),
        ('["https://ok.example.com", null]', "'null'"),
        ('[["https://ok.example.com"]]', "'[\"https://ok.example.com\"]'"),
        # An entry of a JSON list is taken as written: it is not trimmed.
        ('[" https://ok.example.com"]', "' https://ok.example.com'"),
    ],
)
def test_a_json_list_holding_what_is_not_an_origin_is_refused(value, entry):
    with pytest.raises(ImproperlyConfigured) as refused:
        allowed_origins(value)

    message = str(refused.value)
    assert f"{VARIABLE}: {entry} is not an origin" in message
    # The message says both forms the variable takes.
    assert "separated by commas or as a JSON list" in message


@pytest.mark.parametrize(
    "value",
    [
        '["https://dashboard.example.com"',
        '["https://dashboard.example.com",]',
        "[https://dashboard.example.com]",
        '["https://dashboard.example.com"] x',
        "[",
    ],
)
def test_malformed_json_is_refused_and_not_read_as_a_comma_list(value):
    with pytest.raises(ImproperlyConfigured) as refused:
        allowed_origins(value)

    message = str(refused.value)
    assert f"{VARIABLE} starts like a JSON list and is not one" in message
    assert "separated by commas or as a JSON list" in message


def test_a_json_value_that_is_not_a_list_is_not_json_to_guardian():
    """Only a value that starts with ``[`` is read as JSON, as in the gateway."""
    with pytest.raises(ImproperlyConfigured) as refused:
        allowed_origins('{"origin": "https://a.example.com"}')

    assert "is not an origin" in str(refused.value)
    with pytest.raises(ImproperlyConfigured):
        allowed_origins('"https://a.example.com"')


# --- the gateway's grammar -----------------------------------------------------


@pytest.mark.parametrize("value", GATEWAY_REFUSES)
def test_what_the_gateway_refuses_guardian_refuses(value):
    with pytest.raises(ImproperlyConfigured):
        allowed_origins(value)


@pytest.mark.parametrize("value", sorted(GATEWAY_ACCEPTS))
def test_what_the_gateway_starts_on_guardian_starts_on(value):
    """The production overlay gives both the same value: guardian must not
    stop on one the gateway documents and accepts."""
    assert allowed_origins(value) == GATEWAY_ACCEPTS[value]


def test_the_vectors_are_the_ones_the_gateway_is_started_with():
    """If the gateway's own test changes its values, these lists follow."""
    script = GATEWAY_START_UP_TESTS.read_text(encoding="utf-8")

    for value in GATEWAY_REFUSES + sorted(GATEWAY_ACCEPTS):
        quoted = f"'{value}'" if '"' in value else f'"{value}"'
        assert quoted in script, value


def test_the_gateway_parser_is_the_one_this_follows():
    """The points of the grammar guardian/cors.py copies, where it copies them."""
    parser = GATEWAY_PARSER.read_text(encoding="utf-8")

    # A value that starts with [ is JSON; anything else is split on commas.
    assert 'raw:match("^%s*%[")' in parser
    assert 'raw:gmatch("[^,]+")' in parser
    # An origin: lower case, a host of these characters, a port of 1-5 digits.
    assert "local origin = value:lower()" in parser
    assert '"^https?://([a-z0-9.-]+)$"' in parser
    assert '"^https?://([a-z0-9.-]+):%d%d?%d?%d?%d?$"' in parser
    assert '"^https?://%[[0-9a-f:]+%]$"' in parser


@pytest.mark.parametrize(
    "entry",
    [
        "https://-a.example.com",
        "https://a.example.com-",
        "https://.example.com",
        "https://a..example.com",
        "https://a.example.com:123456",
        "https://a.example.com:",
        "https://a_b.example.com",
        "https://a.example.com\n",
    ],
)
def test_a_host_the_gateway_would_not_take_is_refused(entry):
    with pytest.raises(ImproperlyConfigured):
        allowed_origins(json.dumps([entry]))


@pytest.mark.parametrize(
    "entry",
    [
        "*",
        "https://*.example.com",
        "dashboard.example.com",
        "dashboard.example.com:3000",
        "https://dashboard.example.com/",
        "https://dashboard.example.com/app",
        "https://dashboard.example.com?x=1",
        "https://user@dashboard.example.com",
        "ftp://dashboard.example.com",
        "https://",
        "https://dashboard.example.com:port",
        "null",
    ],
)
def test_an_entry_that_is_not_an_origin_is_refused(entry):
    with pytest.raises(ImproperlyConfigured) as refused:
        allowed_origins(f"https://ok.example.com,{entry}")

    assert VARIABLE in str(refused.value)
    assert repr(entry) in str(refused.value)


def test_every_development_origin_is_one_the_variable_would_accept():
    assert allowed_origins(",".join(DEVELOPMENT_ORIGINS)) == list(DEVELOPMENT_ORIGINS)


# --- the settings ------------------------------------------------------------


def _load_settings(**variables):
    """Load guardian's settings in a new interpreter, as a start-up does."""
    env = {key: value for key, value in os.environ.items() if key != VARIABLE}
    env.update(DJANGO_SETTINGS_MODULE="guardian.settings_test", **variables)
    program = (
        "import django; django.setup();"
        "from django.conf import settings as s;"
        "print(s.CORS_ALLOWED_ORIGINS, s.CORS_ALLOW_CREDENTIALS)"
    )
    return subprocess.run(
        [sys.executable, "-c", program],
        cwd=GUARDIAN_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_start_up_without_the_variable_allows_the_development_origins():
    loaded = _load_settings()

    assert loaded.returncode == 0, loaded.stderr[-500:]
    assert loaded.stdout.strip() == f"{list(DEVELOPMENT_ORIGINS)} True"


def test_start_up_applies_the_variable():
    loaded = _load_settings(CORS_ALLOWED_ORIGINS="https://dashboard.example.com")

    assert loaded.returncode == 0, loaded.stderr[-500:]
    assert loaded.stdout.strip() == "['https://dashboard.example.com'] True"


def test_start_up_applies_a_json_list():
    loaded = _load_settings(
        CORS_ALLOWED_ORIGINS='["https://a.example.com", "https://b.example.com"]'
    )

    assert loaded.returncode == 0, loaded.stderr[-500:]
    assert loaded.stdout.strip() == (
        "['https://a.example.com', 'https://b.example.com'] True"
    )


def test_start_up_with_an_empty_variable_allows_no_origin():
    loaded = _load_settings(CORS_ALLOWED_ORIGINS="")

    assert loaded.returncode == 0, loaded.stderr[-500:]
    assert loaded.stdout.strip() == "[] True"


def test_start_up_fails_on_a_wildcard():
    loaded = _load_settings(CORS_ALLOWED_ORIGINS="*")

    assert loaded.returncode != 0
    assert "ImproperlyConfigured" in loaded.stderr
    assert "CORS_ALLOWED_ORIGINS: '*' is not an origin" in loaded.stderr
    assert loaded.stdout == ""


def test_django_cors_headers_accepts_what_the_settings_hold(settings):
    """corsheaders' own system check, on a list read from the variable."""
    from corsheaders.checks import check_settings

    settings.CORS_ALLOWED_ORIGINS = allowed_origins(
        '["https://dashboard.example.com", "http://10.0.0.5:3000", "http://[::1]:3000"]'
    )

    assert check_settings(app_configs=None) == []


# --- the response ------------------------------------------------------------


def _preflight(origin):
    return Client().options(
        "/health/",
        HTTP_ORIGIN=origin,
        HTTP_ACCESS_CONTROL_REQUEST_METHOD="GET",
        HTTP_X_FORWARDED_PROTO="https",
    )


def test_only_a_listed_origin_is_answered(settings):
    settings.CORS_ALLOWED_ORIGINS = allowed_origins("https://dashboard.example.com")

    listed = _preflight("https://dashboard.example.com")
    development = _preflight("http://localhost:3000")

    assert listed["Access-Control-Allow-Origin"] == "https://dashboard.example.com"
    assert "Access-Control-Allow-Origin" not in development


def test_an_empty_list_answers_no_origin(settings):
    settings.CORS_ALLOWED_ORIGINS = allowed_origins("")

    for origin in ("https://dashboard.example.com", "http://localhost:3000"):
        assert "Access-Control-Allow-Origin" not in _preflight(origin)


# --- Compose -----------------------------------------------------------------


def test_the_production_overlay_passes_the_deployment_origins():
    """The line this module makes true: without it the variable is unset in
    production and the development origins are allowed again."""
    text = PROD_OVERLAY.read_text(encoding="utf-8")
    guardian = text.split("\n  guardian:\n", 1)[1].split("\n  responder:\n", 1)[0]

    assert "      - CORS_ALLOWED_ORIGINS=${CORS_ORIGINS}\n" in guardian
