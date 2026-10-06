"""guardian's allowed origins come from the variable Compose passes (#665).

``docker-compose.prod.yml`` passed ``CORS_ALLOWED_ORIGINS=${CORS_ORIGINS}`` to
guardian, whose list of origins was written in its settings: the operator's
origin was never allowed, and the development ones always were.
"""

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


def test_a_trailing_slash_and_a_repeat_are_dropped():
    value = "https://dashboard.example.com/,https://dashboard.example.com"

    assert allowed_origins(value) == ["https://dashboard.example.com"]


@pytest.mark.parametrize(
    "entry",
    [
        "*",
        "https://*.example.com",
        "dashboard.example.com",
        "dashboard.example.com:3000",
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
        "https://dashboard.example.com/, http://10.0.0.5:3000"
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
