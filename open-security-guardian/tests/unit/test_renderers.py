"""The API answers JSON; the browsable API is for development (#724).

``BrowsableAPIRenderer`` was on in every environment. Its pages link static
files through ``{% static %}``; the static storage is WhiteNoise's manifest
storage, which wants the manifest ``collectstatic`` writes; and the image
never runs ``collectstatic``. So any request that asked for ``text/html``
answered 500, "Missing staticfiles manifest entry", on every route. And
where it did render, it was an HTML form for every write the API has.

Outside development there is one renderer, JSON. A request that accepts
only HTML is told so (406); a browser, which also accepts ``*/*``, gets the
JSON.
"""

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView

from tests.unit import team_fixtures as tf

GUARDIAN_DIR = Path(__file__).resolve().parents[2]

_GW_SECRET = "test-gateway-secret"
_JSON = "rest_framework.renderers.JSONRenderer"
_BROWSABLE = "rest_framework.renderers.BrowsableAPIRenderer"
_ASSETS = "/api/v1/assets/assets/"


@pytest.fixture
def get(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)
    caller = str(uuid.uuid4())

    def call(url, team, accept):
        return client.get(
            url,
            secure=True,
            HTTP_ACCEPT=accept,
            HTTP_X_WILDBOX_USER_ID=caller,
            HTTP_X_WILDBOX_TEAM_ID=str(team),
            HTTP_X_WILDBOX_ROLE="admin",
            HTTP_X_WILDBOX_AUTH_TYPE="session",
            HTTP_X_GATEWAY_SECRET=_GW_SECRET,
        )

    return call


def test_outside_development_the_only_renderer_is_json(settings):
    assert settings.DEBUG is False
    assert settings.REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] == [_JSON]


def _renderers(debug):
    """DEFAULT_RENDERER_CLASSES of a start-up with ``DEBUG`` set to ``debug``."""
    env = dict(os.environ, DEBUG=debug)
    loaded = subprocess.run(
        [
            sys.executable,
            "-c",
            "import guardian.settings_test as s;"
            "print(' '.join(s.REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES']))",
        ],
        cwd=GUARDIAN_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert loaded.returncode == 0, loaded.stderr[-500:]
    return loaded.stdout.split()


def test_the_browsable_api_is_served_with_debug_only():
    assert _renderers("true") == [_JSON, _BROWSABLE]
    assert _renderers("false") == [_JSON]
    # What is not exactly "true" is not development.
    assert _renderers("1") == [_JSON]


def _api_views(patterns=None):
    for entry in get_resolver().url_patterns if patterns is None else patterns:
        if isinstance(entry, URLResolver):
            if str(entry.pattern).startswith("admin"):
                continue
            yield from _api_views(entry.url_patterns)
        elif isinstance(entry, URLPattern):
            view = getattr(entry.callback, "cls", None) or getattr(
                entry.callback, "view_class", None
            )
            if view is not None and issubclass(view, APIView):
                yield view


def test_no_view_brings_a_renderer_of_its_own():
    views = set(_api_views())
    assert len(views) > 40
    for view in views:
        assert view.renderer_classes == [JSONRenderer], view.__name__


@pytest.mark.django_db
@pytest.mark.parametrize("detail", [False, True])
def test_a_request_for_html_is_told_there_is_none(get, detail):
    """It answered 500: "Missing staticfiles manifest entry"."""
    from apps.assets.models import Asset

    team = uuid.uuid4()
    asset = tf.make(Asset, team)
    url = f"{_ASSETS}{asset.pk}/" if detail else _ASSETS

    response = get(url, team, "text/html")

    assert response.status_code == 406, response.content[:300]
    assert response["Content-Type"] == "application/json"
    assert "Accept" in response.json()["detail"]


@pytest.mark.django_db
def test_a_browser_gets_the_json(get):
    from apps.assets.models import Asset

    team = uuid.uuid4()
    asset = tf.make(Asset, team)
    browser = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

    response = get(_ASSETS, team, browser)

    assert response.status_code == 200, response.content[:300]
    assert response["Content-Type"] == "application/json"
    assert [row["id"] for row in response.json()["results"]] == [str(asset.pk)]


@pytest.mark.django_db
def test_an_error_is_json_whatever_was_asked_for(get):
    response = get(f"{_ASSETS}{uuid.uuid4()}/", uuid.uuid4(), "text/html, */*")

    assert response.status_code == 404
    assert response["Content-Type"] == "application/json"
