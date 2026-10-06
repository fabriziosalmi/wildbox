"""guardian keeps no credential of a scanner or an external system (#728).

Five columns held secrets as plain text: ``Scanner.api_key`` and
``Scanner.password`` (the help text of the second said "Encrypted"),
``ExternalSystem.auth_config``, ``WebhookEndpoint.secret_token`` and
``NotificationChannel.config``. The API took them and never returned them,
and nothing in guardian read them: it connects to no scanner, contacts no
external system, receives no webhook and delivers nothing through a
channel. Whoever could read the database, a dump or a backup read every
team's credentials, and nobody else ever could.

A secret kept for nobody is not worth a key to encrypt it with, so the
columns are gone. These tests hold four things:

- the columns do not exist, on the models or in the tables, and no model
  field or served serializer field is named like a secret unless this file
  says how it is protected;
- the API answers 400 for a value sent in one of the five fields, instead
  of answering "created" and discarding it, and nothing of the value
  reaches the database or the response;
- the migrations remove the values from a database that holds them, tell
  the operator how many rows had one without printing any, and add nothing
  back when reversed;
- ``RefusedFieldsMixin`` refuses values and lets empty ones through.
"""

import importlib
import logging
import re
import types
import uuid

import pytest
from django.apps import apps as django_apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.operations import RemoveField, RunPython
from django.db.migrations.recorder import MigrationRecorder
from django.http import QueryDict
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework import serializers
from rest_framework.generics import GenericAPIView

from tests.unit import team_fixtures as tf

_GW_SECRET = "test-gateway-secret"
#: Part of every secret these tests send or store; it must turn up nowhere.
MARKER = "s3cr3t-728"

#: (app, model, column): what held a secret and no longer exists.
REMOVED = [
    ("scanners", "Scanner", "api_key"),
    ("scanners", "Scanner", "password"),
    ("integrations", "ExternalSystem", "auth_config"),
    ("integrations", "WebhookEndpoint", "secret_token"),
    ("integrations", "NotificationChannel", "config"),
]

#: A field with one of these in its name is taken for a secret.
SECRET_NAME = re.compile(
    r"passw|secret|token|api_?key|credential|private_?key|auth_config", re.I
)

#: ``{"app.Model.field" or "SerializerName.field": how it is protected}``.
#: Empty: guardian stores no secret. A field that needs to be here is
#: encrypted with a key the database does not hold (as cspm does,
#: open-security-cspm/app/credential_crypto.py), write-only in the API, and
#: has a reader; say so in the value.
PROTECTED = {}


def _database_text():
    """Every value of every row of every table, as text."""
    chunks = []
    with connection.cursor() as cursor:
        for table in connection.introspection.table_names(cursor):
            cursor.execute(f"SELECT * FROM {connection.ops.quote_name(table)}")
            chunks.extend(repr(row) for row in cursor.fetchall())
    return "\n".join(chunks)


def _columns(table):
    with connection.cursor() as cursor:
        return {
            column.name
            for column in connection.introspection.get_table_description(cursor, table)
        }


def _table(app, model):
    return f"{app}_{model.lower()}"


# --- nothing is stored --------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("app, model, column", REMOVED)
def test_the_column_does_not_exist(app, model, column):
    cls = django_apps.get_model(app, model)
    assert column not in {field.name for field in cls._meta.get_fields()}
    assert column not in _columns(cls._meta.db_table)


def _own_models():
    return [m for m in django_apps.get_models() if m.__module__.startswith("apps.")]


def test_no_model_field_is_named_like_a_secret():
    models = _own_models()
    # Guards the loop below against looking at nothing.
    assert len(models) > 40
    found = [
        f"{model._meta.label}.{field.name}"
        for model in models
        for field in model._meta.get_fields()
        if SECRET_NAME.search(field.name)
    ]
    unexplained = sorted(set(found) - set(PROTECTED))
    assert not unexplained, (
        f"{unexplained} look like stored secrets. guardian stores none "
        "(#728): either nothing reads the field and it should not exist, or "
        "it is encrypted with a key the database does not hold and listed "
        "in PROTECTED with how."
    )


def test_the_methods_that_returned_them_are_gone():
    from apps.integrations.models import ExternalSystem
    from apps.scanners.models import Scanner

    assert not hasattr(Scanner, "get_connection_info")
    assert not hasattr(ExternalSystem, "get_auth_headers")


def _walk(patterns, prefix=""):
    for entry in patterns:
        part = str(entry.pattern).lstrip("^").rstrip("$")
        if isinstance(entry, URLResolver):
            yield from _walk(entry.url_patterns, prefix + part)
        elif isinstance(entry, URLPattern):
            yield prefix + part, entry.callback


def _served_serializers():
    """Every serializer class a route of the API can use, from the URLconf."""
    found = {}
    for path, callback in _walk(get_resolver().url_patterns):
        view_cls = getattr(callback, "cls", None)
        actions = getattr(callback, "actions", None) or {}
        if not path.startswith("api/v1/") or view_cls is None:
            continue
        for action in actions.values():
            view = view_cls()
            view.action = action
            view.request = None
            view.format_kwarg = None
            view.kwargs = {}
            if not isinstance(view, GenericAPIView):
                continue
            if (
                view.serializer_class is None
                and type(view).get_serializer_class
                is GenericAPIView.get_serializer_class
            ):
                # A view that answers without a serializer.
                continue
            found.setdefault(view.get_serializer_class(), path)
    return found


def test_no_served_serializer_has_a_field_named_like_a_secret():
    served = _served_serializers()
    names = {cls.__name__ for cls in served}
    # Guards against a walk that finds nothing, and names the four
    # serializers this is about.
    assert len(served) > 40
    assert {
        "ScannerDetailSerializer",
        "ExternalSystemSerializer",
        "WebhookEndpointSerializer",
        "NotificationChannelSerializer",
    } <= names
    found = []
    for serializer_cls, path in served.items():
        for name in serializer_cls().fields:
            label = f"{serializer_cls.__name__}.{name}"
            if SECRET_NAME.search(name) and label not in PROTECTED:
                found.append(f"{label} ({path})")
    assert not found, (
        f"{sorted(found)}: the API reads or writes a field named like a "
        "secret. See PROTECTED in this file."
    )


@pytest.mark.parametrize("app, model, column", REMOVED)
def test_no_served_serializer_has_a_removed_field(app, model, column):
    cls = django_apps.get_model(app, model)
    for serializer_cls in _served_serializers():
        meta = getattr(serializer_cls, "Meta", None)
        if getattr(meta, "model", None) is cls:
            assert column not in serializer_cls().fields, serializer_cls.__name__


# --- the API refuses what it would not keep -----------------------------------


@pytest.fixture
def api(settings, monkeypatch):
    # The throttles use the default cache, which is Redis outside the tests.
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", _GW_SECRET)
    client = Client(raise_request_exception=False)

    def call(method, url, team, data=None, content_type="application/json"):
        kwargs = {
            "secure": True,
            "HTTP_X_WILDBOX_USER_ID": str(uuid.uuid4()),
            "HTTP_X_WILDBOX_TEAM_ID": str(team),
            "HTTP_X_WILDBOX_ROLE": "admin",
            "HTTP_X_WILDBOX_AUTH_TYPE": "session",
            "HTTP_X_GATEWAY_SECRET": _GW_SECRET,
        }
        if data is not None:
            kwargs.update(data=data)
            if content_type is not None:
                kwargs.update(content_type=content_type)
        return getattr(client, method)(url, **kwargs)

    return call


@pytest.fixture
def team():
    return uuid.uuid4()


def _scanner_body(team):
    return {
        "name": "nessus",
        "scanner_type": "nessus",
        "base_url": "https://scanner.example.com",
        "username": "svc-guardian",
    }


def _system_body(team):
    return {
        "name": "jira",
        "system_type": "ticketing",
        "base_url": "https://jira.example.com",
        "auth_type": "bearer",
    }


def _webhook_body(team):
    return {
        "system": str(tf.external_system(team).pk),
        "name": "hook",
        "endpoint_url": "/hooks/jira",
    }


def _channel_body(team):
    return {"name": "slack", "channel_type": "slack", "recipients": ["#security"]}


#: (id, route, the row a detail request names, a body the route accepts,
#: the refused field, a secret for it)
CASES = [
    (
        "scanner-api-key",
        "scanners/scanners",
        tf.scanner,
        _scanner_body,
        "api_key",
        f"{MARKER}-api-key",
    ),
    (
        "scanner-password",
        "scanners/scanners",
        tf.scanner,
        _scanner_body,
        "password",
        f"{MARKER}-password",
    ),
    (
        "system-auth-config",
        "integrations/systems",
        tf.external_system,
        _system_body,
        "auth_config",
        {"token": f"{MARKER}-token", "key_header": "X-API-Key"},
    ),
    (
        "webhook-secret",
        "integrations/webhooks",
        tf.webhook,
        _webhook_body,
        "secret_token",
        f"{MARKER}-webhook",
    ),
    (
        "channel-config",
        "integrations/notifications",
        tf.notification_channel,
        _channel_body,
        "config",
        {"webhook_url": f"https://hooks.slack.com/services/{MARKER}"},
    ),
]
_IDS = [case[0] for case in CASES]


def _model(route):
    return {
        "scanners/scanners": ("scanners", "Scanner"),
        "integrations/systems": ("integrations", "ExternalSystem"),
        "integrations/webhooks": ("integrations", "WebhookEndpoint"),
        "integrations/notifications": ("integrations", "NotificationChannel"),
    }[route]


def _assert_refused(response, field):
    assert response.status_code == 400, response.content[:500]
    body = response.json()
    assert list(body) == [field], body
    assert "does not store" in body[field][0]
    # The refusal names the field, never what was sent in it.
    assert MARKER.encode() not in response.content


@pytest.mark.django_db
@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_a_create_that_sends_a_secret_is_refused(api, team, case, caplog):
    _, route, _, body, field, secret = case
    model = django_apps.get_model(*_model(route))
    data = {**body(team), field: secret}

    with caplog.at_level(logging.DEBUG):
        response = api("post", f"/api/v1/{route}/", team, data)

    _assert_refused(response, field)
    assert not model.objects.exists()
    # Not in a row (an audit entry, a history row), not in a log line.
    assert MARKER not in _database_text()
    assert MARKER not in caplog.text


@pytest.mark.django_db
@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_the_same_create_without_the_secret_is_accepted(api, team, case):
    _, route, _, body, field, _ = case
    model = django_apps.get_model(*_model(route))

    response = api("post", f"/api/v1/{route}/", team, body(team))

    assert response.status_code == 201, response.content[:500]
    assert field not in response.json()
    assert model.objects.count() == 1


@pytest.mark.django_db
@pytest.mark.parametrize("case", CASES, ids=_IDS)
@pytest.mark.parametrize("method", ["patch", "put"])
def test_an_update_that_sends_a_secret_is_refused(api, team, case, method):
    _, route, factory, body, field, secret = case
    row = factory(team)
    before = type(row).objects.filter(pk=row.pk).values().get()
    data = {field: secret}
    if method == "put":
        data = {**body(team), **data}
        if "system" in data:
            data["system"] = str(row.system_id)
            data["endpoint_url"] = row.endpoint_url

    response = api(method, f"/api/v1/{route}/{row.pk}/", team, data)

    _assert_refused(response, field)
    assert type(row).objects.filter(pk=row.pk).values().get() == before
    assert MARKER not in _database_text()


@pytest.mark.django_db
@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_a_form_post_that_sends_a_secret_is_refused(api, team, case):
    _, route, _, body, field, secret = case
    if not isinstance(secret, str):
        pytest.skip("a form field carries text, not an object")
    model = django_apps.get_model(*_model(route))
    form = {
        key: value
        for key, value in {**body(team), field: secret}.items()
        if not isinstance(value, list)
    }

    response = api("post", f"/api/v1/{route}/", team, form, content_type=None)

    _assert_refused(response, field)
    assert not model.objects.exists()


@pytest.mark.django_db
@pytest.mark.parametrize("case", CASES, ids=_IDS)
@pytest.mark.parametrize("empty", ["", None, {}, []], ids=repr)
def test_an_empty_value_is_not_a_secret(api, team, case, empty):
    """Nothing was sent, so nothing is lost: a form that fills every key works."""
    _, route, factory, _, field, _ = case
    row = factory(team)

    response = api("patch", f"/api/v1/{route}/{row.pk}/", team, {field: empty})

    assert response.status_code == 200, response.content[:500]
    assert field not in response.json()


@pytest.mark.django_db
@pytest.mark.parametrize("case", CASES, ids=_IDS)
def test_a_read_has_no_such_field(api, team, case):
    _, route, factory, _, field, _ = case
    row = factory(team)

    listed = api("get", f"/api/v1/{route}/", team)
    retrieved = api("get", f"/api/v1/{route}/{row.pk}/", team)

    assert listed.status_code == retrieved.status_code == 200
    assert field not in retrieved.json()
    assert all(field not in entry for entry in listed.json()["results"])


# --- RefusedFieldsMixin -------------------------------------------------------


def _probe(data):
    from apps.core.refused_fields import RefusedFieldsMixin

    class Probe(RefusedFieldsMixin, serializers.Serializer):
        refused_fields = {"secret": "not kept", "token": "not kept either"}
        name = serializers.CharField()

    return Probe(data=data)


def test_a_value_in_a_refused_field_is_an_error_on_that_field():
    probe = _probe({"name": "n", "secret": MARKER})
    assert not probe.is_valid()
    assert probe.errors == {"secret": ["not kept"]}
    assert MARKER not in str(probe.errors)


def test_every_refused_field_sent_is_named():
    probe = _probe({"name": "n", "secret": MARKER, "token": {"a": MARKER}})
    assert not probe.is_valid()
    assert set(probe.errors) == {"secret", "token"}


def test_a_refusal_comes_before_the_other_errors():
    # No ``name``: the caller still learns the secret was not taken.
    probe = _probe({"secret": MARKER})
    assert not probe.is_valid()
    assert set(probe.errors) == {"secret"}


def test_form_data_is_refused_like_json():
    probe = _probe(QueryDict(f"name=n&secret={MARKER}"))
    assert not probe.is_valid()
    assert set(probe.errors) == {"secret"}


@pytest.mark.parametrize("empty", ["", None, {}, []], ids=repr)
def test_an_empty_refused_field_is_let_through(empty):
    probe = _probe({"name": "n", "secret": empty})
    assert probe.is_valid(), probe.errors
    assert probe.validated_data == {"name": "n"}


def test_a_body_without_the_field_is_untouched():
    probe = _probe({"name": "n"})
    assert probe.is_valid(), probe.errors


def test_a_body_that_is_not_an_object_gets_the_usual_error():
    probe = _probe([MARKER])
    assert not probe.is_valid()
    assert "non_field_errors" in probe.errors


# --- the migrations -----------------------------------------------------------

BEFORE = [
    ("scanners", "0002_team_id"),
    ("integrations", "0003_webhook_path_unique_per_system"),
]
#: The migrations to undo to get there, newest first, each with the one
#: before it in its app. integrations.0005 (#665) came after the two this
#: file is about and has to go first: the executor does not go back to a
#: migration behind an applied one, so with it left in place the upgrade
#: below would find nothing to apply.
UNDO = [
    (
        ("integrations", "0005_drop_unwritten_log_payloads"),
        ("integrations", "0004_drop_stored_credentials"),
    ),
    (
        ("scanners", "0003_drop_stored_credentials"),
        ("scanners", "0002_team_id"),
    ),
    (
        ("integrations", "0004_drop_stored_credentials"),
        ("integrations", "0003_webhook_path_unique_per_system"),
    ),
]


def _reverse():
    """Undo the migrations, as ``migrate <app> <previous>`` would.

    Returns the models of the schema that had the columns. Each migration's
    own ``unapply`` runs, without the executor around it: going backwards,
    the executor renders the models of every migration of every app first,
    which takes longer than the rest of this file.
    """
    loader = MigrationLoader(connection)
    recorder = MigrationRecorder(connection)
    for (app, name), previous in UNDO:
        if (app, name) not in recorder.applied_migrations():
            continue
        with connection.schema_editor() as editor:
            loader.get_migration(app, name).unapply(
                loader.project_state([previous]), editor
            )
        recorder.record_unapplied(app, name)
    return loader.project_state(BEFORE).apps


def _upgrade():
    """What the image's entrypoint does at start: ``manage.py migrate``."""
    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())


@pytest.fixture
def old_apps():
    """The models of 0.11.2, on its schema; the current schema afterwards."""
    try:
        yield _reverse()
    finally:
        _upgrade()


def _store_secrets(old_apps):
    """One row with a secret and one without, per column, as 0.11 stored them."""
    Scanner = old_apps.get_model("scanners", "Scanner")
    ExternalSystem = old_apps.get_model("integrations", "ExternalSystem")
    WebhookEndpoint = old_apps.get_model("integrations", "WebhookEndpoint")
    NotificationChannel = old_apps.get_model("integrations", "NotificationChannel")
    team = uuid.uuid4()

    Scanner.objects.create(
        team_id=team,
        name="with-key",
        scanner_type="nessus",
        base_url="https://a.example.com",
        api_key=f"{MARKER}-api-key",
    )
    Scanner.objects.create(
        team_id=team,
        name="with-password",
        scanner_type="qualys",
        base_url="https://b.example.com",
        username="svc",
        password=f"{MARKER}-password",
    )
    Scanner.objects.create(
        team_id=team,
        name="without",
        scanner_type="openvas",
        base_url="https://c.example.com",
    )
    system = ExternalSystem.objects.create(
        team_id=team,
        name="with-token",
        system_type="ticketing",
        base_url="https://jira.example.com",
        auth_type="basic",
        auth_config={"username": "svc", "password": f"{MARKER}-basic"},
    )
    ExternalSystem.objects.create(
        team_id=team,
        name="without",
        system_type="siem",
        base_url="https://siem.example.com",
    )
    WebhookEndpoint.objects.create(
        system=system,
        name="with-secret",
        endpoint_url="/hooks/a",
        secret_token=f"{MARKER}-webhook",
    )
    WebhookEndpoint.objects.create(
        system=system, name="without", endpoint_url="/hooks/b"
    )
    NotificationChannel.objects.create(
        team_id=team,
        name="with-url",
        channel_type="slack",
        config={"webhook_url": f"https://hooks.slack.com/services/{MARKER}"},
    )
    NotificationChannel.objects.create(
        team_id=team,
        name="without",
        channel_type="email",
        config={},
    )


def _names(model_apps):
    return {
        (app, model): sorted(
            model_apps.get_model(app, model).objects.values_list("name", flat=True)
        )
        for app, model in {(app, model) for app, model, _ in REMOVED}
    }


@pytest.mark.django_db(transaction=True)
def test_the_upgrade_removes_the_stored_secrets(old_apps, caplog):
    _store_secrets(old_apps)
    rows_before = _names(old_apps)
    # The state #728 describes: the secrets are readable in the database.
    assert _database_text().count(MARKER) == 5

    with caplog.at_level(logging.WARNING):
        _upgrade()

    assert MARKER not in _database_text()
    for app, model, column in REMOVED:
        assert column not in _columns(_table(app, model))
    # The records stay: only the secrets went.
    assert _names(django_apps) == rows_before
    scanner = django_apps.get_model("scanners", "Scanner").objects.get(
        name="with-password"
    )
    assert (scanner.username, scanner.base_url) == ("svc", "https://b.example.com")

    # The operator is told how many rows held one, and no value.
    assert MARKER not in caplog.text
    messages = [record.getMessage() for record in caplog.records]
    for count, rows in [
        (2, "scanner(s)"),
        (1, "external system(s)"),
        (1, "webhook endpoint(s)"),
        (1, "notification channel(s)"),
    ]:
        assert any(f"for {count} {rows}" in m for m in messages), (rows, messages)

    # Applying it again changes nothing and does not fail.
    _upgrade()
    assert _names(django_apps) == rows_before


@pytest.mark.django_db(transaction=True)
def test_reversing_the_upgrade_restores_nothing(old_apps):
    _store_secrets(old_apps)
    _upgrade()

    reversed_apps = _reverse()

    for app, model, column in REMOVED:
        assert column in _columns(_table(app, model))
        values = reversed_apps.get_model(app, model).objects.values_list(
            column, flat=True
        )
        assert len(values) >= 2
        assert not any(values), (model, column)
    assert MARKER not in _database_text()


#: (the migration, the app whose columns it empties, the rows of
#: ``_store_secrets`` it has to report)
BLANKING = [
    ("apps.scanners.migrations.0003_drop_stored_credentials", "scanners", 1),
    ("apps.integrations.migrations.0004_drop_stored_credentials", "integrations", 3),
]


def _held(model_apps):
    """``{app: [whether each row still holds a secret]}``, columns present."""
    held = {}
    for app, model, column in REMOVED:
        assert column in _columns(_table(app, model))
        values = model_apps.get_model(app, model).objects.values_list(column, flat=True)
        held.setdefault(app, []).extend(bool(value) for value in values)
    return held


@pytest.mark.django_db(transaction=True)
def test_the_values_are_blanked_before_the_columns_are_dropped(old_apps, caplog):
    """``DROP COLUMN`` alone leaves the bytes in the PostgreSQL row.

    So the step that empties the columns is run on its own here, on the
    schema that still has them: afterwards they exist and hold nothing.
    Each migration empties its own app's columns and reports one line per
    kind of row that held a secret.
    """
    _store_secrets(old_apps)
    editor = types.SimpleNamespace(connection=connection)
    assert all(any(rows) for rows in _held(old_apps).values())

    emptied = set()
    for module, app, lines in BLANKING:
        migration = importlib.import_module(module)
        blank = migration.blank_credentials
        # It is the first thing the migration does, ahead of every drop.
        first, *drops = migration.Migration.operations
        assert isinstance(first, RunPython) and first.code is blank, module
        assert drops and all(isinstance(drop, RemoveField) for drop in drops)

        caplog.clear()
        with caplog.at_level(logging.WARNING):
            blank(old_apps, editor)
        emptied.add(app)

        assert len(caplog.records) == lines, caplog.text
        assert MARKER not in caplog.text
        for held_app, rows in _held(old_apps).items():
            assert any(rows) == (held_app not in emptied), (module, held_app)

        # Again, on rows already empty: nothing to do and nothing to say.
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            blank(old_apps, editor)
        assert not caplog.records

    assert MARKER not in _database_text()
