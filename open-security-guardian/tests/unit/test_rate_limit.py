"""guardian's throttle: one rate, per gateway user, set by a variable (#645).

``API_RATE_LIMIT`` was documented as guardian's rate limit and reached
nothing: docker-compose.yml did not pass it. Had it been passed, the one
value would have replaced two different defaults, 100 an hour for anonymous
callers and 1000 for users. Anonymous callers do not exist under ``/api/``
(the middleware refuses them), so that throttle met one route only, the
health check, and refused the container's own probe for ten minutes of
every hour.

Now: ``GUARDIAN_RATE_LIMIT_USER``, passed by compose, checked when the
settings load, counted per user as the gateway forwards the user.
"""

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import yaml
from apps.core.throttling import GatewayUserRateThrottle
from django.core.exceptions import ImproperlyConfigured
from django.test import Client, RequestFactory
from guardian.rate_limit import (
    LEGACY_RATE_VARIABLE,
    USER_RATE_DEFAULT,
    USER_RATE_VARIABLE,
    user_rate,
)

GUARDIAN_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = GUARDIAN_DIR.parent
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
PROD_OVERLAY = REPO_ROOT / "docker-compose.prod.yml"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

_GW_SECRET = "test-gateway-secret"
_ASSETS = "/api/v1/assets/assets/"
_THROTTLE = "apps.core.throttling.GatewayUserRateThrottle"


# --- the variable ------------------------------------------------------------


def test_the_default_is_a_thousand_an_hour():
    assert USER_RATE_DEFAULT == "1000/hour"
    assert user_rate(environ={}) == "1000/hour"


@pytest.mark.parametrize(
    "value, rate",
    [
        ("500/hour", "500/hour"),
        ("20/minute", "20/minute"),
        ("5/second", "5/second"),
        ("10000/day", "10000/day"),
        # The short forms DRF's own examples use.
        ("20/min", "20/minute"),
        ("5/s", "5/second"),
        ("7/m", "7/minute"),
        ("9/h", "9/hour"),
        ("3/d", "3/day"),
        ("  250/Hour  ", "250/hour"),
        ("999999999/day", "999999999/day"),
    ],
)
def test_a_rate_is_read(value, rate):
    assert user_rate(environ={USER_RATE_VARIABLE: value}) == rate


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_variable_means_the_default(value):
    """So compose can pass it through as ``${GUARDIAN_RATE_LIMIT_USER:-}``."""
    assert user_rate(environ={USER_RATE_VARIABLE: value}) == USER_RATE_DEFAULT


@pytest.mark.parametrize("value", ["off", "OFF", " Off "])
def test_off_means_no_throttle(value):
    assert user_rate(environ={USER_RATE_VARIABLE: value}) is None


@pytest.mark.parametrize(
    "value",
    [
        "1000",
        "lots",
        "lots/hour",
        "10/fortnight",
        "10/hamster",  # DRF reads the first letter: an hour
        "10/hours",
        "0/hour",
        "-5/hour",
        "+5/hour",
        "1e3/hour",
        "10.5/hour",
        "10/",
        "/hour",
        "10 / hour",
        "10/hour/day",
        "10/5m",
        "1000000000/hour",
        "none",
        "false",
    ],
)
def test_a_malformed_rate_stops_start_up(value):
    with pytest.raises(ImproperlyConfigured, match=USER_RATE_VARIABLE) as raised:
        user_rate(environ={USER_RATE_VARIABLE: value})
    # The message shows the value and what was expected.
    assert repr(value) in str(raised.value)
    assert "1000/hour" in str(raised.value)


def test_the_former_name_is_still_read():
    assert user_rate(environ={LEGACY_RATE_VARIABLE: "300/hour"}) == "300/hour"


def test_the_new_name_wins_over_the_former():
    environ = {USER_RATE_VARIABLE: "40/minute", LEGACY_RATE_VARIABLE: "300/hour"}
    assert user_rate(environ=environ) == "40/minute"
    # An empty new variable, as compose passes it, does not hide the former.
    environ[USER_RATE_VARIABLE] = ""
    assert user_rate(environ=environ) == "300/hour"


def test_a_malformed_former_name_stops_start_up_too():
    with pytest.raises(ImproperlyConfigured, match=LEGACY_RATE_VARIABLE):
        user_rate(environ={LEGACY_RATE_VARIABLE: "lots"})


# --- the settings ------------------------------------------------------------


def test_settings_install_the_user_throttle_only(settings):
    rest = settings.REST_FRAMEWORK

    assert rest["DEFAULT_THROTTLE_RATES"] == {"user": user_rate()}
    assert "anon" not in rest["DEFAULT_THROTTLE_RATES"]
    expected = [_THROTTLE] if user_rate() else []
    assert rest["DEFAULT_THROTTLE_CLASSES"] == expected


def _load_settings(**variables):
    """Load guardian's settings in a new interpreter, as a start-up does."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in (USER_RATE_VARIABLE, LEGACY_RATE_VARIABLE)
    }
    env.update(DJANGO_SETTINGS_MODULE="guardian.settings_test", **variables)
    program = (
        "import django; django.setup();"
        "from django.conf import settings as s;"
        "r = s.REST_FRAMEWORK;"
        "print(r['DEFAULT_THROTTLE_RATES'], r['DEFAULT_THROTTLE_CLASSES'])"
    )
    return subprocess.run(
        [sys.executable, "-c", program],
        cwd=GUARDIAN_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_start_up_applies_the_variable():
    loaded = _load_settings(GUARDIAN_RATE_LIMIT_USER="7/minute")

    assert loaded.returncode == 0, loaded.stderr[-500:]
    assert loaded.stdout.strip() == f"{{'user': '7/minute'}} ['{_THROTTLE}']"


def test_start_up_with_off_installs_no_throttle():
    loaded = _load_settings(GUARDIAN_RATE_LIMIT_USER="off")

    assert loaded.returncode == 0, loaded.stderr[-500:]
    assert loaded.stdout.strip() == "{'user': None} []"


@pytest.mark.parametrize("variable", [USER_RATE_VARIABLE, LEGACY_RATE_VARIABLE])
def test_start_up_fails_on_a_malformed_rate(variable):
    loaded = _load_settings(**{variable: "lots"})

    assert loaded.returncode != 0
    assert "ImproperlyConfigured" in loaded.stderr
    assert f"{variable}='lots'" in loaded.stderr
    assert loaded.stdout == ""


# --- the throttle ------------------------------------------------------------


@pytest.fixture
def client(settings, monkeypatch):
    # The throttle uses the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    # Three a minute, so a test reaches the limit in four requests.
    monkeypatch.setattr(GatewayUserRateThrottle, "THROTTLE_RATES", {"user": "3/minute"})
    return Client(raise_request_exception=False)


def _as(user_id, team_id, **extra):
    headers = {
        "HTTP_X_WILDBOX_USER_ID": str(user_id),
        "HTTP_X_WILDBOX_TEAM_ID": str(team_id),
        "HTTP_X_WILDBOX_ROLE": "admin",
        "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
    }
    headers.update(extra)
    return headers


def _statuses(client, count, **headers):
    return [
        client.get(_ASSETS, secure=True, **headers).status_code for _ in range(count)
    ]


def test_views_carry_the_user_throttle():
    from apps.assets.views import AssetViewSet
    from apps.core.views import HealthCheckView, TaskStatusView

    assert AssetViewSet.throttle_classes == [GatewayUserRateThrottle]
    assert TaskStatusView.throttle_classes == [GatewayUserRateThrottle]
    assert HealthCheckView.throttle_classes == []


@pytest.mark.django_db
def test_a_user_over_the_rate_is_refused(client):
    headers = _as(uuid.uuid4(), uuid.uuid4())

    assert _statuses(client, 3, **headers) == [200, 200, 200]
    refused = client.get(_ASSETS, secure=True, **headers)

    assert refused.status_code == 429
    assert refused.json()["detail"].startswith("Request was throttled.")
    assert int(refused["Retry-After"]) > 0


@pytest.mark.django_db
def test_each_user_has_a_budget_of_their_own(client):
    """Two members of a team, both behind the gateway's one address."""
    team = uuid.uuid4()
    gateway = {"REMOTE_ADDR": "172.18.0.9"}
    first, second = _as(uuid.uuid4(), team, **gateway), _as(
        uuid.uuid4(), team, **gateway
    )

    assert _statuses(client, 4, **first) == [200, 200, 200, 429]
    assert _statuses(client, 3, **second) == [200, 200, 200]


@pytest.mark.django_db
def test_the_budget_follows_the_user_not_the_address(client):
    """Neither another address nor another X-Forwarded-For starts a new one."""
    user, team = uuid.uuid4(), uuid.uuid4()

    statuses = [
        client.get(
            _ASSETS,
            secure=True,
            **_as(
                user,
                team,
                REMOTE_ADDR=f"172.18.0.{number}",
                HTTP_X_FORWARDED_FOR=f"198.51.100.{number}",
            ),
        ).status_code
        for number in range(1, 5)
    ]

    assert statuses == [200, 200, 200, 429]


def test_the_key_is_the_gateway_user():
    class _GatewayUser:
        user_id = "5f0c5bd2-4e0b-4d5c-9a55-1d0e3c1f6b7a"

    request = RequestFactory().get(_ASSETS, REMOTE_ADDR="172.18.0.9")
    request.gateway_user = _GatewayUser()
    throttle = GatewayUserRateThrottle()

    assert throttle.get_cache_key(request, None) == (
        "throttle_user_5f0c5bd2-4e0b-4d5c-9a55-1d0e3c1f6b7a"
    )
    # A request the gateway did not authenticate is counted under nothing.
    assert throttle.get_cache_key(RequestFactory().get("/health/"), None) is None


@pytest.mark.django_db
def test_the_health_check_is_never_throttled(client):
    """130 probes from one address: more than an hour of container checks."""
    statuses = {
        client.get("/health/", REMOTE_ADDR="127.0.0.1").status_code for _ in range(130)
    }

    assert statuses == {200}


# --- compose -----------------------------------------------------------------


class _Replaced(list):
    """A list a Compose overlay marks ``!override`` or ``!reset``."""


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that reads Compose's tags instead of refusing them."""


def _tagged(loader, _suffix, node):
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return _Replaced(loader.construct_sequence(node, deep=True))
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _tagged)


def _service(path, name):
    services = yaml.load(  # nosec B506 - a SafeLoader subclass
        path.read_text(encoding="utf-8"), Loader=_ComposeLoader
    )["services"]
    return services[name]


def _environment(service):
    entries = service.get("environment") or []
    if isinstance(entries, dict):
        return {
            key: "" if value is None else str(value) for key, value in entries.items()
        }
    return dict(entry.split("=", 1) for entry in entries)


_PASSED = "${GUARDIAN_RATE_LIMIT_USER:-}"

needs_checkout = pytest.mark.skipif(
    not COMPOSE_FILE.exists(), reason="needs the repository checkout"
)


@needs_checkout
def test_compose_passes_the_variable_to_guardian():
    environment = _environment(_service(COMPOSE_FILE, "guardian"))

    # Empty when unset, which user_rate() reads as the default.
    assert environment.get(USER_RATE_VARIABLE) == _PASSED
    assert user_rate(environ={USER_RATE_VARIABLE: ""}) == USER_RATE_DEFAULT


@needs_checkout
def test_the_production_overlay_keeps_it():
    """Compose merges ``environment`` by name unless the overlay replaces it."""
    overlay = _service(PROD_OVERLAY, "guardian")
    # The loader does see a replaced list: guardian's networks are one.
    assert isinstance(overlay["networks"], _Replaced)

    environment = {}
    if not isinstance(overlay.get("environment"), _Replaced):
        environment.update(_environment(_service(COMPOSE_FILE, "guardian")))
    environment.update(_environment(overlay))

    assert environment.get(USER_RATE_VARIABLE) == _PASSED


@needs_checkout
def test_the_variable_is_documented_where_compose_reads_it():
    documented = [
        line
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
        if line.lstrip("# ").startswith(f"{USER_RATE_VARIABLE}=")
    ]
    assert len(documented) == 1, documented
    # The example value is one guardian accepts.
    assert user_rate(environ={USER_RATE_VARIABLE: documented[0].split("=", 1)[1]})
