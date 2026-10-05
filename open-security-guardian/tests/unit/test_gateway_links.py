"""Pagination links are the ones a client of the gateway can follow (#643).

The gateway serves guardian's ``/api/v1/<x>`` as ``/api/v1/guardian/<x>`` and
presents guardian its container name as ``Host``. DRF's stock paginator built
``next`` and ``previous`` from that request, so every list of more than one
page answered ``http://open-security-guardian/api/v1/...``: a host no client
resolves, without the gateway's path, and a disclosure of the internal
topology.

The links are now relative references under the path the gateway reports in
``X-Forwarded-Prefix``. Nothing in them comes from a host header, the
caller's or guardian's own.
"""

import re
import uuid
from pathlib import Path

import pytest
from apps.assets.models import Asset
from apps.core.pagination import API_ROOT, GatewayPageNumberPagination, public_uri
from django.test import Client
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

_GW_SECRET = "test-gateway-secret"
_ASSETS = "/api/v1/assets/assets/"
_PUBLIC_ASSETS = "/api/v1/guardian/assets/assets/"
_PREFIX = "/api/v1/guardian"
_INTERNAL_HOST = "open-security-guardian"

REPO_ROOT = Path(__file__).resolve().parents[3]
GATEWAY_CONF = (
    REPO_ROOT / "open-security-gateway" / "nginx" / "conf.d" / "wildbox_gateway.conf"
)


@pytest.fixture
def client(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    return Client(raise_request_exception=False)


@pytest.fixture
def team(db):
    """A team with 51 assets: one more than a page."""
    team_id = uuid.uuid4()
    Asset.objects.bulk_create(
        Asset(team_id=team_id, name=f"asset-{number:02d}") for number in range(51)
    )
    return team_id


def _through_gateway(team_id, **extra):
    """The headers of a request the gateway forwarded, as guardian gets them."""
    headers = {
        "HTTP_HOST": _INTERNAL_HOST,
        "HTTP_X_FORWARDED_HOST": "gw.example",
        "HTTP_X_FORWARDED_PROTO": "https",
        "HTTP_X_FORWARDED_PREFIX": _PREFIX,
        "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
        "HTTP_X_WILDBOX_TEAM_ID": str(team_id),
        "HTTP_X_WILDBOX_ROLE": "admin",
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
    }
    headers.update(extra)
    return headers


def _page(client, path, **headers):
    response = client.get(path, secure=True, **headers)
    assert response.status_code == 200, response.content[:300]
    return response


def test_next_is_the_gateway_path_without_a_host(client, team):
    response = _page(client, _ASSETS, **_through_gateway(team))
    body = response.json()

    assert body["count"] == 51
    assert body["next"] == f"{_PUBLIC_ASSETS}?page=2"
    assert body["previous"] is None
    assert _INTERNAL_HOST not in response.content.decode()


def test_previous_and_the_other_parameters_are_kept(client, team):
    response = _page(
        client, f"{_ASSETS}?ordering=name&page=2", **_through_gateway(team)
    )
    body = response.json()

    assert [row["name"] for row in body["results"]] == ["asset-50"]
    assert body["next"] is None
    # Page 1 is the list without the parameter, as DRF writes it.
    assert body["previous"] == f"{_PUBLIC_ASSETS}?ordering=name"
    assert _INTERNAL_HOST not in response.content.decode()


def test_the_link_maps_back_to_the_route_guardian_serves(client, team):
    """What the gateway does with the link: its prefix for guardian's root."""
    headers = _through_gateway(team)
    link = _page(client, f"{_ASSETS}?ordering=name", **headers).json()["next"]

    assert link.startswith(_PREFIX + "/")
    followed = _page(client, API_ROOT + link[len(_PREFIX) :], **headers).json()
    assert [row["name"] for row in followed["results"]] == ["asset-50"]


def test_no_host_header_reaches_the_links(client, team):
    """Not the caller's forwarded host, and not the Host guardian was given."""
    response = _page(
        client,
        _ASSETS,
        **_through_gateway(
            team,
            HTTP_X_FORWARDED_HOST="evil.example",
            HTTP_X_FORWARDED_PORT="8443",
            HTTP_FORWARDED="host=evil.example;proto=http",
        ),
    )

    assert response.json()["next"] == f"{_PUBLIC_ASSETS}?page=2"
    assert "evil.example" not in response.content.decode()


@pytest.mark.parametrize(
    "prefix",
    [
        "//evil.example",
        "https://evil.example",
        "/api/v1/../admin",
        "/api/v1/guardian/",
        "/api/v1/guardian?x=1",
        "/api/v1/guard ian",
        "api/v1/guardian",
        "/" + "a" * 300,
        "",
    ],
)
def test_a_prefix_that_is_not_a_plain_path_is_not_used(client, team, prefix):
    """The gateway sets the header itself; anything else is left out."""
    response = _page(
        client, _ASSETS, **_through_gateway(team, HTTP_X_FORWARDED_PREFIX=prefix)
    )

    assert response.json()["next"] == f"{_ASSETS}?page=2"
    assert "evil.example" not in response.content.decode()


def test_without_the_header_the_link_is_guardians_own_path(client, team):
    headers = _through_gateway(team)
    del headers["HTTP_X_FORWARDED_PREFIX"]
    response = _page(client, _ASSETS, **headers)

    assert response.json()["next"] == f"{_ASSETS}?page=2"
    assert _INTERNAL_HOST not in response.content.decode()


def _drf_request(path, gateway=True, **headers):
    request = APIRequestFactory().get(path, HTTP_HOST=_INTERNAL_HOST, **headers)
    if gateway:
        # What GatewayAuthMiddleware leaves on a request it authenticated.
        request.gateway_user = object()
    return Request(request)


def test_the_prefix_is_read_from_gateway_requests_only():
    """A request the middleware did not authenticate names no prefix."""
    path = f"{_ASSETS}?page=3"

    assert (
        public_uri(_drf_request(path, HTTP_X_FORWARDED_PREFIX=_PREFIX))
        == f"{_PUBLIC_ASSETS}?page=3"
    )
    assert (
        public_uri(_drf_request(path, gateway=False, HTTP_X_FORWARDED_PREFIX=_PREFIX))
        == path
    )


def test_a_path_outside_the_api_root_is_left_alone():
    request = _drf_request("/health/?page=1", HTTP_X_FORWARDED_PREFIX=_PREFIX)
    assert public_uri(request) == "/health/?page=1"


def test_the_html_page_controls_use_the_same_links():
    """The browsable renderer's page links, built by get_html_context()."""
    paginator = GatewayPageNumberPagination()
    request = _drf_request(f"{_ASSETS}?page=2", HTTP_X_FORWARDED_PREFIX=_PREFIX)
    paginator.paginate_queryset(list(range(120)), request)

    context = paginator.get_html_context()

    assert context["previous_url"] == _PUBLIC_ASSETS
    assert context["next_url"] == f"{_PUBLIC_ASSETS}?page=3"
    urls = [link.url for link in context["page_links"] if link.url]
    assert urls == [
        _PUBLIC_ASSETS,
        f"{_PUBLIC_ASSETS}?page=2",
        f"{_PUBLIC_ASSETS}?page=3",
    ]


def test_the_schema_describes_references_not_absolute_uris():
    """The OpenAPI schema (served in DEBUG) says what the links are."""
    schema = GatewayPageNumberPagination().get_paginated_response_schema(
        {"type": "array"}
    )

    for name in ("next", "previous"):
        link = schema["properties"][name]
        assert link["format"] == "uri-reference"
        assert link["nullable"] is True
        assert link["example"].startswith(f"{_PUBLIC_ASSETS}?page=")
    assert schema["properties"]["results"] == {"type": "array"}


def test_every_list_is_paginated_by_the_gateway_class(settings):
    from django.urls import get_resolver
    from rest_framework.pagination import BasePagination

    assert (
        settings.REST_FRAMEWORK["DEFAULT_PAGINATION_CLASS"]
        == "apps.core.pagination.GatewayPageNumberPagination"
    )

    def views(patterns):
        for pattern in patterns:
            if hasattr(pattern, "url_patterns"):
                yield from views(pattern.url_patterns)
            elif hasattr(pattern.callback, "cls"):
                yield pattern.callback.cls

    paginated = {
        cls
        for cls in views(get_resolver().url_patterns)
        if getattr(cls, "pagination_class", None) is not None
    }
    assert paginated, "no paginated view found: the walk above is broken"
    for cls in paginated:
        assert issubclass(cls.pagination_class, BasePagination)
        assert issubclass(
            cls.pagination_class, GatewayPageNumberPagination
        ), f"{cls.__name__} builds its links with {cls.pagination_class.__name__}"


# --- the gateway's half ------------------------------------------------------


def _guardian_location():
    """The body of the gateway's guardian location, comments removed."""
    text = GATEWAY_CONF.read_text(encoding="utf-8")
    match = re.search(
        r"^    location (/api/v1/guardian/) \{\n(.*?)^    \}", text, re.M | re.S
    )
    assert match, "the guardian location is gone from wildbox_gateway.conf"
    lines = [
        line.strip()
        for line in match.group(2).splitlines()
        if not line.strip().startswith("#")
    ]
    return match.group(1), [line for line in lines if line]


@pytest.mark.skipif(not GATEWAY_CONF.exists(), reason="needs the repository checkout")
def test_the_gateway_names_the_prefix_it_serves_guardian_under():
    """The header says where the location is, and replaces the client's own.

    ``proxy_set_header`` with a literal value: the caller's X-Forwarded-Prefix
    never reaches guardian. The value has to be the location's own path, and
    the location has to map onto the root the links are rebuilt from.
    """
    location, directives = _guardian_location()

    assert f"proxy_set_header X-Forwarded-Prefix {_PREFIX};" in directives
    assert location == _PREFIX + "/"
    assert f"proxy_pass http://guardian_service{API_ROOT}/;" in directives
    # Set once: a second directive would make nginx send two values.
    assert sum("X-Forwarded-Prefix" in line for line in directives) == 1
