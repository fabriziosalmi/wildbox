"""A discovery is checked before it is queued, and a rule that never runs is
not "enabled" (#724).

``POST assets/assets/discover/`` took ``network_range`` as it came. A value
that is not a network answered "Asset discovery initiated" with a task id;
the worker found out, and retried three times. ``10.0.0.0/8`` was accepted
too: sixteen million connection attempts in one task. A discovery rule
checked that its networks parse, and not how large they are.

And a discovery rule of a type guardian does not implement, which the
dispatcher never runs, could be switched on: ``enable/`` answered "enabled".
"""

import importlib
import json
import uuid
from pathlib import Path
from unittest import mock

import pytest
from apps.assets import tasks
from apps.assets.models import AssetDiscoveryRule
from apps.assets.networks import (
    MAX_RULE_NETWORKS,
    MAX_SCAN_ADDRESSES,
    NetworkRefused,
    scan_network,
)
from django.test import Client

from tests.unit import team_fixtures as tf

GUARDIAN_DIR = Path(__file__).resolve().parents[2]
_GW_SECRET = "test-gateway-secret"
_DISCOVER = "/api/v1/assets/assets/discover/"
_RULES = "/api/v1/assets/discovery-rules/"


@pytest.fixture
def api(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)
    caller = str(uuid.uuid4())

    def call(method, url, team, data=None):
        kwargs = {
            "secure": True,
            "HTTP_X_WILDBOX_USER_ID": caller,
            "HTTP_X_WILDBOX_TEAM_ID": str(team),
            "HTTP_X_WILDBOX_ROLE": "admin",
            "HTTP_X_WILDBOX_AUTH_TYPE": "session",
            "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        }
        if data is not None:
            kwargs.update(data=json.dumps(data), content_type="application/json")
        return getattr(client, method)(url, **kwargs)

    return call


@pytest.fixture
def queued():
    """The discoveries queued, instead of a broker: [(args, kwargs), ...]."""
    calls = []

    def delay(*args, **kwargs):
        calls.append((args, kwargs))
        return mock.Mock(id=str(uuid.uuid4()))

    with mock.patch.object(tasks.discover_assets, "delay", side_effect=delay):
        yield calls


# --- the bound, and where it comes from -----------------------------------------


def test_the_bound_is_the_tools_services():
    """One number for "how much may be scanned in one request" on the platform."""
    policy = GUARDIAN_DIR.parent / "open-security-tools" / "app" / "target_policy.py"
    if not policy.exists():
        pytest.skip("needs the repository checkout")
    assert f"MAX_TARGET_ADDRESSES = {MAX_SCAN_ADDRESSES}\n" in policy.read_text()
    assert MAX_SCAN_ADDRESSES == 1024


@pytest.mark.parametrize(
    "value, network",
    [
        ("192.0.2.0/24", "192.0.2.0/24"),
        ("192.0.2.77/24", "192.0.2.0/24"),
        (" 192.0.2.0/30 ", "192.0.2.0/30"),
        ("192.0.2.9", "192.0.2.9/32"),
        ("10.0.0.0/22", "10.0.0.0/22"),
        ("2001:db8::/118", "2001:db8::/118"),
    ],
)
def test_a_network_within_the_bound_is_accepted(value, network):
    assert str(scan_network(value)) == network
    assert scan_network(value).num_addresses <= MAX_SCAN_ADDRESSES


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.0/21",
        "10.0.0.0/8",
        "0.0.0.0/0",
        "2001:db8::/117",
        "::/0",
        "not a network",
        "10.0.0.0/33",
        "10.0.0.1-10.0.0.9",
        "example.com",
        "",
        "   ",
        None,
        ["10.0.0.0/24"],
        {"cidr": "10.0.0.0/24"},
        1,
    ],
)
def test_anything_else_is_refused_with_the_reason(value):
    with pytest.raises(NetworkRefused) as refused:
        scan_network(value)
    assert str(refused.value)


def test_the_refusal_does_not_repeat_an_endless_value():
    with pytest.raises(NetworkRefused) as refused:
        scan_network("x" * 5000)
    assert len(str(refused.value)) < 200


# --- discover/ ---------------------------------------------------------------------


@pytest.mark.django_db
def test_discover_queues_a_network_within_the_bound(api, queued):
    team = uuid.uuid4()

    response = api("post", _DISCOVER, team, {"network_range": "192.0.2.77/24"})

    assert response.status_code == 200, response.content[:300]
    assert response.json()["task_id"]
    # The network, as normalized, and the caller's team.
    assert queued == [(("192.0.2.0/24", "basic"), {"team_id": str(team)})]


@pytest.mark.django_db
@pytest.mark.parametrize(
    "body",
    [
        {"network_range": "10.0.0.0/8"},
        {"network_range": "10.0.0.0/21"},
        {"network_range": "0.0.0.0/0"},
        {"network_range": "::/0"},
        {"network_range": "not a network"},
        {"network_range": "192.0.2.0/33"},
        {"network_range": ["192.0.2.0/24"]},
        {"network_range": 7},
        {"network_range": ""},
        {},
    ],
)
def test_discover_refuses_before_queueing(api, queued, body):
    response = api("post", _DISCOVER, uuid.uuid4(), body)

    assert response.status_code == 400, response.content[:300]
    assert response.json()["network_range"]
    assert queued == []


@pytest.mark.django_db
def test_discover_refuses_a_scan_type_it_does_not_have(api, queued):
    team = uuid.uuid4()
    body = {"network_range": "192.0.2.0/30", "scan_type": "stealth"}

    response = api("post", _DISCOVER, team, body)

    assert response.status_code == 400
    assert "comprehensive" in str(response.json()["scan_type"])
    assert queued == []
    body["scan_type"] = "comprehensive"
    assert api("post", _DISCOVER, team, body).status_code == 200
    assert queued[0][0] == ("192.0.2.0/30", "comprehensive")


# --- the task, for what was stored before the check ----------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("network_range", ["10.0.0.0/8", "not a network"])
def test_the_task_refuses_what_the_api_refuses_and_does_not_retry(network_range):
    with mock.patch.object(tasks, "_host_is_up") as probe:
        result = tasks.discover_assets.apply(args=(network_range,))

    assert result.successful()
    assert result.get()["status"] == "refused"
    assert result.get()["reason"]
    probe.assert_not_called()


@pytest.mark.django_db
def test_the_task_sweeps_a_network_within_the_bound():
    with mock.patch.object(tasks, "_host_is_up", return_value=False) as probe:
        result = tasks.discover_assets.apply(args=("192.0.2.0/30",))

    assert result.get()["status"] == "completed"
    assert [call.args[0] for call in probe.call_args_list] == ["192.0.2.1", "192.0.2.2"]


@pytest.mark.django_db
def test_a_stored_rule_queues_only_the_networks_that_may_be_swept(queued):
    team = uuid.uuid4()
    rule = tf.make(AssetDiscoveryRule, team)
    AssetDiscoveryRule.objects.filter(pk=rule.pk).update(
        target_specification={"networks": ["10.0.0.0/8", "192.0.2.0/30", "bogus"]}
    )

    result = tasks.execute_discovery_rule.apply(args=(rule.pk,)).get()

    assert result["networks_queued"] == 1
    assert [args[0] for args, _ in queued] == ["192.0.2.0/30"]


# --- a rule's networks ---------------------------------------------------------------


def _rule(**fields):
    body = {
        "name": f"rule-{uuid.uuid4().hex[:8]}",
        "discovery_type": "network_scan",
        "target_specification": {"networks": ["192.0.2.0/30"]},
        "schedule": "*/10 * * * *",
    }
    body.update(fields)
    return body


@pytest.mark.django_db
@pytest.mark.parametrize(
    "specification",
    [
        {"networks": ["10.0.0.0/8"]},
        {"networks": ["192.0.2.0/30", "10.0.0.0/21"]},
        {
            "networks": [
                f"10.0.{number}.0/24" for number in range(MAX_RULE_NETWORKS + 1)
            ]
        },
        {"networks": ["192.0.2.0/30"], "scan_type": "stealth"},
    ],
)
def test_a_rule_is_refused_for_what_its_runs_would_refuse(api, specification):
    team = uuid.uuid4()

    response = api("post", _RULES, team, _rule(target_specification=specification))

    assert response.status_code == 400, response.content[:300]
    assert response.json()["target_specification"]
    assert not AssetDiscoveryRule.objects.exists()


@pytest.mark.django_db
def test_a_rule_within_the_bounds_is_stored(api):
    team = uuid.uuid4()
    networks = [f"10.0.{number * 4}.0/22" for number in range(MAX_RULE_NETWORKS)]
    specification = {"networks": networks, "scan_type": "comprehensive"}

    response = api("post", _RULES, team, _rule(target_specification=specification))

    assert response.status_code == 201, response.content[:300]


# --- a rule that never runs cannot be enabled ------------------------------------------


def _legacy_rule(team, discovery_type="cloud_api", enabled=False):
    """A rule of a type that is not implemented, stored before #548."""
    rule = tf.make(AssetDiscoveryRule, team)
    AssetDiscoveryRule.objects.filter(pk=rule.pk).update(
        discovery_type=discovery_type,
        target_specification={"provider": "aws"},
        enabled=enabled,
    )
    return rule


@pytest.mark.django_db
@pytest.mark.parametrize(
    "discovery_type", ["cloud_api", "cmdb_import", "agent_report", "dns_zone"]
)
def test_enable_refuses_a_rule_of_a_type_that_never_runs(api, discovery_type):
    team = uuid.uuid4()
    rule = _legacy_rule(team, discovery_type)

    response = api("post", f"{_RULES}{rule.pk}/enable/", team)

    assert response.status_code == 501, response.content[:300]
    assert response.json()["code"] == "DISCOVERY_TYPE_NOT_IMPLEMENTED"
    assert discovery_type in response.json()["detail"]
    assert AssetDiscoveryRule.objects.get(pk=rule.pk).enabled is False


@pytest.mark.django_db
def test_a_patch_cannot_enable_it_either(api):
    team = uuid.uuid4()
    rule = _legacy_rule(team)
    url = f"{_RULES}{rule.pk}/"

    refused = api("patch", url, team, {"enabled": True})

    assert refused.status_code == 400, refused.content[:300]
    assert "never run" in str(refused.json()["enabled"])
    assert AssetDiscoveryRule.objects.get(pk=rule.pk).enabled is False
    # Everything else about it can still be edited, and it can be deleted.
    assert api("patch", url, team, {"description": "kept"}).status_code == 200
    assert api("patch", url, team, {"enabled": False}).status_code == 200
    assert api("post", f"{url}disable/", team).status_code == 200
    assert api("delete", url, team).status_code == 204


@pytest.mark.django_db
def test_a_rule_that_runs_is_enabled_as_before(api):
    team = uuid.uuid4()
    rule = tf.make(AssetDiscoveryRule, team)
    AssetDiscoveryRule.objects.filter(pk=rule.pk).update(enabled=False)
    url = f"{_RULES}{rule.pk}/"

    assert api("post", f"{url}enable/", team).status_code == 200
    assert AssetDiscoveryRule.objects.get(pk=rule.pk).enabled is True
    AssetDiscoveryRule.objects.filter(pk=rule.pk).update(enabled=False)
    assert api("patch", url, team, {"enabled": True}).status_code == 200
    assert AssetDiscoveryRule.objects.get(pk=rule.pk).enabled is True


def test_the_types_a_rule_may_have_are_the_models_choices():
    """The four refused above are every choice that is not implemented."""
    from apps.assets.models import IMPLEMENTED_DISCOVERY_TYPES

    choices = {
        value
        for value, _ in AssetDiscoveryRule._meta.get_field("discovery_type").choices
    }
    assert choices - set(IMPLEMENTED_DISCOVERY_TYPES) == {
        "cloud_api",
        "cmdb_import",
        "agent_report",
        "dns_zone",
    }


@pytest.mark.django_db
def test_the_migration_switches_off_the_stored_rules_that_never_run():
    from django.apps import apps

    migration = importlib.import_module(
        "apps.assets.migrations.0003_disable_rules_that_never_run"
    )
    team = uuid.uuid4()
    idle = _legacy_rule(team, "cloud_api", enabled=True)
    already_off = _legacy_rule(team, "dns_zone", enabled=False)
    running = tf.make(AssetDiscoveryRule, team)
    assert running.enabled is True

    migration.disable(apps, None)

    enabled = dict(AssetDiscoveryRule.objects.values_list("pk", "enabled"))
    assert enabled == {idle.pk: False, already_off.pk: False, running.pk: True}
    from apps.assets.models import IMPLEMENTED_DISCOVERY_TYPES

    assert migration.IMPLEMENTED == IMPLEMENTED_DISCOVERY_TYPES
