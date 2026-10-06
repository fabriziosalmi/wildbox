"""A discovery rule says what its last run did (#775).

A rule's run queues one discovery for each of its networks, after the check
a discovery itself makes (#724, #748). A rule stored before that check, or
before the operator narrowed ``GUARDIAN_ALLOWED_INTERNAL_TARGETS``, can name
networks the check refuses: the run skipped them, wrote the reason in
``guardian-worker``'s log, and ended ``completed`` with ``networks_queued:
0``. Its owner had ``last_run`` moving on every schedule and no way to learn
that nothing was swept: the task route answers with a state and no result.

The run now says which networks it did not queue and why, in the task's
result and in ``last_run_result`` on the rule, which the API serves; and a
run that queued nothing is ``skipped``, not ``completed``.
"""

import json
import uuid
from unittest import mock

import pytest
from apps.assets import tasks
from apps.assets.models import AssetDiscoveryRule
from apps.assets.networks import MAX_RULE_NETWORKS, check_network
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import Client
from guardian.scan_targets import ALLOWLIST_VARIABLE, allowed_internal_targets

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"
_RULES = "/api/v1/assets/discovery-rules/"


@pytest.fixture(autouse=True)
def allow(settings):
    """The operator's list, empty to begin with as in a deployment."""

    def set_allowlist(raw):
        settings.SCAN_ALLOWED_INTERNAL_TARGETS = allowed_internal_targets(
            {ALLOWLIST_VARIABLE: raw}
        )

    set_allowlist("")
    return set_allowlist


@pytest.fixture
def api(settings, monkeypatch):
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
    """The networks a discovery was queued for, instead of a broker."""
    networks = []

    def delay(network_range, *args, **kwargs):
        networks.append(network_range)
        return mock.Mock(id=str(uuid.uuid4()))

    with mock.patch.object(tasks.discover_assets, "delay", side_effect=delay):
        yield networks


def _rule(team, networks):
    """A rule that names ``networks``, as one stored before any check."""
    rule = tf.make(AssetDiscoveryRule, team)
    AssetDiscoveryRule.objects.filter(pk=rule.pk).update(
        target_specification={"networks": networks}
    )
    rule.refresh_from_db()
    return rule


def _run(rule):
    result = tasks.execute_discovery_rule.apply(args=(rule.pk,))
    assert result.successful()
    return result.get()


def _refusal(network):
    refusal = check_network(network)[1]
    assert refusal is not None
    return refusal


# --- a run that swept nothing ------------------------------------------------------


@pytest.mark.django_db
def test_a_rule_whose_networks_are_all_refused_does_not_end_completed(queued):
    internal = ["10.0.0.0/24", "fd00::/118", "169.254.169.254/32"]
    rule = _rule(uuid.uuid4(), internal)

    result = _run(rule)

    assert queued == []
    assert result == {
        "status": "skipped",
        "reason": "no_network_queued",
        "rule_name": rule.name,
        "networks_queued": 0,
        "networks_skipped_count": 3,
        "networks_skipped": [
            {"network": network, "reason": _refusal(network)} for network in internal
        ],
    }
    # Each reason is the one the API gives when the network is typed: it
    # names the setting to ask the operator for.
    for skipped in result["networks_skipped"]:
        assert "an internal address" in skipped["reason"]
        assert ALLOWLIST_VARIABLE in skipped["reason"]


@pytest.mark.django_db
def test_the_rules_owner_reads_it_on_the_rule(api, queued):
    """The task route answers with a state; the worker's log is the operator's."""
    team = uuid.uuid4()
    rule = _rule(team, ["10.0.0.0/24", "192.168.1.0/24"])

    before = api("get", f"{_RULES}{rule.pk}/", team).json()
    assert before["last_run"] is None and before["last_run_result"] is None

    result = _run(rule)

    record = api("get", f"{_RULES}{rule.pk}/", team)
    assert record.status_code == 200, record.content[:300]
    served = record.json()["last_run_result"]
    assert record.json()["last_run"] is not None
    assert served == {key: value for key, value in result.items() if key != "rule_name"}
    assert served["status"] == "skipped" and served["networks_queued"] == 0
    assert [skipped["network"] for skipped in served["networks_skipped"]] == [
        "10.0.0.0/24",
        "192.168.1.0/24",
    ]
    assert all(ALLOWLIST_VARIABLE in s["reason"] for s in served["networks_skipped"])
    # In the list too, and only for the team the rule belongs to.
    (listed,) = api("get", _RULES, team).json()["results"]
    assert listed["last_run_result"] == served
    assert api("get", f"{_RULES}{rule.pk}/", uuid.uuid4()).status_code == 404


@pytest.mark.django_db
def test_a_rule_with_no_network_at_all_did_not_complete_either(queued):
    result = _run(_rule(uuid.uuid4(), []))

    assert result["status"] == "skipped" and result["reason"] == "no_network_queued"
    assert result["networks_queued"] == 0 and result["networks_skipped"] == []


# --- a run that swept some, or all ---------------------------------------------------


@pytest.mark.django_db
def test_a_run_names_the_networks_it_left_out_and_why(queued):
    too_large = "8.0.0.0/8"
    rule = _rule(
        uuid.uuid4(),
        ["8.8.8.0/30", "172.18.0.0/24", too_large, "not a network", "1.1.1.0/30"],
    )

    result = _run(rule)

    assert queued == ["8.8.8.0/30", "1.1.1.0/30"]
    assert result["status"] == "completed" and "reason" not in result
    assert result["networks_queued"] == 2 and result["networks_skipped_count"] == 3
    reasons = {s["network"]: s["reason"] for s in result["networks_skipped"]}
    assert list(reasons) == ["172.18.0.0/24", too_large, "not a network"]
    assert ALLOWLIST_VARIABLE in reasons["172.18.0.0/24"]
    assert "Split it into smaller networks" in reasons[too_large]
    assert reasons["not a network"].endswith("is not a network in CIDR notation.")
    rule.refresh_from_db()
    assert rule.last_run_result["networks_skipped"] == result["networks_skipped"]


@pytest.mark.django_db
def test_a_run_that_queued_every_network_says_so(queued, allow):
    allow("192.168.50.0/24")
    rule = _rule(uuid.uuid4(), ["8.8.8.0/30", "192.168.50.0/28"])

    result = _run(rule)

    assert queued == ["8.8.8.0/30", "192.168.50.0/28"]
    assert result == {
        "status": "completed",
        "rule_name": rule.name,
        "networks_queued": 2,
        "networks_skipped_count": 0,
        "networks_skipped": [],
    }
    rule.refresh_from_db()
    assert rule.last_run_result == {
        "status": "completed",
        "networks_queued": 2,
        "networks_skipped_count": 0,
        "networks_skipped": [],
    }


@pytest.mark.django_db
def test_the_result_is_the_last_runs(queued, allow):
    """The operator lists the range: the next run says what it then did."""
    rule = _rule(uuid.uuid4(), ["192.168.50.0/28"])
    assert _run(rule)["status"] == "skipped"

    allow("192.168.50.0/24")
    assert _run(rule)["status"] == "completed"

    rule.refresh_from_db()
    assert rule.last_run_result["networks_skipped"] == []
    assert rule.last_run_result["networks_queued"] == 1
    assert "reason" not in rule.last_run_result


# --- a network the broker did not take ----------------------------------------------


@pytest.mark.django_db
def test_a_scan_that_could_not_be_queued_is_not_counted_and_is_named():
    rule = _rule(uuid.uuid4(), ["8.8.8.0/30", "1.1.1.0/30"])
    failure = ConnectionError("Error 111 connecting to redis://:hunter2@broker:6379/1")

    with mock.patch.object(tasks.discover_assets, "delay", side_effect=failure):
        result = _run(rule)

    assert result["status"] == "skipped" and result["networks_queued"] == 0
    assert result["networks_skipped"] == [
        {"network": "8.8.8.0/30", "reason": tasks.NOT_QUEUED},
        {"network": "1.1.1.0/30", "reason": tasks.NOT_QUEUED},
    ]
    # guardian's own words: the exception names the broker.
    rule.refresh_from_db()
    for text in (json.dumps(result), json.dumps(rule.last_run_result)):
        assert "hunter2" not in text and "redis" not in text and "broker" not in text


@pytest.mark.django_db
def test_the_log_of_a_scan_that_could_not_be_queued_names_the_error_not_its_text(
    caplog,
):
    """The result was guardian's own words and the log line was not (#788):
    it held the broker exception's text, the broker's URL with it."""
    rule = _rule(uuid.uuid4(), ["8.8.8.0/30"])
    failure = ConnectionError("Error 111 connecting to redis://:hunter2@broker:6379/1")

    with caplog.at_level("DEBUG", logger="apps.assets.tasks"):
        with mock.patch.object(tasks.discover_assets, "delay", side_effect=failure):
            _run(rule)

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "hunter2" not in logged and "redis://" not in logged
    assert "broker:6379" not in logged
    # What happened, to which network, and what kind of error it was.
    (line,) = [
        record
        for record in caplog.records
        if record.levelname == "ERROR" and "8.8.8.0/30" in record.getMessage()
    ]
    assert "ConnectionError" in line.getMessage()


# --- what is kept is bounded, and is the run's ------------------------------------------


@pytest.mark.django_db
def test_what_is_kept_of_a_rule_with_many_networks_is_bounded(queued):
    """A rule stored before the API bounded the list names any number."""
    many = [f"10.{index}.0.0/24" for index in range(MAX_RULE_NETWORKS + 8)]
    rule = _rule(uuid.uuid4(), many)

    result = _run(rule)

    assert result["networks_skipped_count"] == MAX_RULE_NETWORKS + 8
    assert len(result["networks_skipped"]) == MAX_RULE_NETWORKS
    assert [s["network"] for s in result["networks_skipped"]] == many[
        :MAX_RULE_NETWORKS
    ]
    rule.refresh_from_db()
    assert len(rule.last_run_result["networks_skipped"]) == MAX_RULE_NETWORKS


@pytest.mark.django_db
def test_a_stored_value_that_is_not_a_short_string_is_named_shortly(queued):
    rule = _rule(uuid.uuid4(), ["x" * 5000, 5, None, {"cidr": "10.0.0.0/8"}])

    result = _run(rule)

    names = [skipped["network"] for skipped in result["networks_skipped"]]
    assert names == ["x" * 64, "5", "None", "{'cidr': '10.0.0.0/8'}"]
    assert all(len(skipped["reason"]) < 200 for skipped in result["networks_skipped"])


@pytest.mark.django_db
def test_a_request_cannot_write_the_result(api, queued):
    team = uuid.uuid4()
    forged = {"status": "completed", "networks_queued": 99, "networks_skipped": []}
    body = {
        "name": "lab",
        "discovery_type": "network_scan",
        "target_specification": {"networks": ["8.8.8.0/30"]},
        "schedule": "*/10 * * * *",
        "last_run_result": forged,
    }

    created = api("post", _RULES, team, body)

    assert created.status_code == 201, created.content[:300]
    assert created.json()["last_run_result"] is None
    rule = AssetDiscoveryRule.objects.get(pk=created.json()["id"])
    for method, data in (("patch", {"last_run_result": forged}), ("put", body)):
        response = api(method, f"{_RULES}{rule.pk}/", team, data)
        assert response.status_code == 200, response.content[:300]
        assert response.json()["last_run_result"] is None
    rule.refresh_from_db()
    assert rule.last_run_result is None


@pytest.mark.django_db
def test_an_edit_that_crosses_a_run_does_not_put_the_run_before_back(queued):
    """A rule read before the run ended and saved after it, as the API saves."""
    rule = _rule(uuid.uuid4(), ["10.0.0.0/24"])
    _run(rule)
    read_before = AssetDiscoveryRule.objects.get(pk=rule.pk)
    assert read_before.last_run_result["status"] == "skipped"

    AssetDiscoveryRule.objects.filter(pk=rule.pk).update(
        target_specification={"networks": ["8.8.8.0/30"]}
    )
    assert _run(rule)["status"] == "completed"

    read_before.description = "edited"
    read_before.save()

    rule.refresh_from_db()
    assert rule.description == "edited"
    assert rule.last_run_result["status"] == "completed"

    # Nor when the edit reschedules the rule.
    stale = AssetDiscoveryRule.objects.get(pk=rule.pk)
    stale.last_run_result = {"status": "skipped"}
    stale.schedule = "0 3 * * *"
    stale.save()
    rule.refresh_from_db()
    assert rule.schedule == "0 3 * * *"
    assert rule.last_run_result["status"] == "completed"


# --- the upgrade ------------------------------------------------------------------------

_BEFORE = ("assets", "0003_disable_rules_that_never_run")
_COLUMN = ("assets", "0004_discovery_rule_last_run_result")


def _columns():
    with connection.cursor() as cursor:
        described = connection.introspection.get_table_description(
            cursor, AssetDiscoveryRule._meta.db_table
        )
    return {column.name for column in described}


@pytest.fixture
def before_the_column():
    """guardian's database as 0.12.0 left it, with the rules of two teams."""
    executor = MigrationExecutor(connection)
    executor.migrate([_BEFORE])
    old = executor.loader.project_state([_BEFORE]).apps
    rule = old.get_model("assets", "AssetDiscoveryRule")
    stored = [
        rule.objects.create(
            team_id=uuid.uuid4(),
            name=f"stored-{index}",
            discovery_type="network_scan",
            target_specification={"networks": ["10.0.0.0/24"]},
            schedule="*/5 * * * *",
            enabled=bool(index),
        ).pk
        for index in range(2)
    ]
    yield stored
    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())


@pytest.mark.django_db(transaction=True)
def test_the_upgrade_adds_one_empty_column_and_keeps_every_rule(before_the_column):
    assert "last_run_result" not in _columns()
    kept = list(AssetDiscoveryRule.objects.order_by("name").values_list("pk", "name"))

    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())

    assert "last_run_result" in _columns()
    rules = AssetDiscoveryRule.objects.order_by("name")
    assert [(rule.pk, rule.name) for rule in rules] == kept
    assert [rule.pk for rule in rules] == before_the_column
    assert [rule.last_run_result for rule in rules] == [None, None]
    assert [rule.enabled for rule in rules] == [False, True]
    assert rules[0].target_specification == {"networks": ["10.0.0.0/24"]}
    # And it is the next run that fills it.
    with mock.patch.object(tasks.discover_assets, "delay"):
        assert _run(rules[1])["status"] == "skipped"
    assert (
        AssetDiscoveryRule.objects.get(pk=rules[1].pk).last_run_result[
            "networks_skipped_count"
        ]
        == 1
    )


@pytest.mark.django_db(transaction=True)
def test_the_column_can_be_taken_back_and_the_rules_stay(before_the_column):
    executor = MigrationExecutor(connection)
    executor.migrate([_COLUMN])
    assert "last_run_result" in _columns()

    executor = MigrationExecutor(connection)
    executor.migrate([_BEFORE])

    assert "last_run_result" not in _columns()
    old = executor.loader.project_state([_BEFORE]).apps
    rule = old.get_model("assets", "AssetDiscoveryRule")
    assert sorted(rule.objects.values_list("pk", flat=True)) == sorted(
        before_the_column
    )


# --- a rule that does not run records nothing ---------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"enabled": False}, "rule_disabled"),
        ({"discovery_type": "cloud_api"}, "not_implemented"),
    ],
)
def test_a_rule_that_does_not_run_keeps_the_result_of_its_last_run(
    queued, change, reason
):
    rule = _rule(uuid.uuid4(), ["8.8.8.0/30"])
    _run(rule)
    AssetDiscoveryRule.objects.filter(pk=rule.pk).update(**change)

    assert _run(rule) == {"status": "skipped", "reason": reason}

    rule.refresh_from_db()
    assert rule.last_run_result["status"] == "completed"
    assert queued == ["8.8.8.0/30"]
