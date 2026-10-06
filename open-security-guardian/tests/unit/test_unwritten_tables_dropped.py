"""What guardian never wrote is no longer in its schema, or in its code (#665).

Four things were left that nothing wrote, read or reached:

- ``VulnerabilityAttachment``: a table without a writer. Its only reader,
  ``vulnerabilities/{id}/attachments/``, went in #724. Migration
  ``vulnerabilities.0004`` drops the table when it is empty and refuses when
  it is not, leaving every row where it was.
- ``IntegrationLog.request_data`` and ``response_data``: columns for the raw
  payloads of calls guardian does not make. Migration ``integrations.0005``
  drops them.
- ``/admin/``: Django's admin site, mounted with no model registered.
- ``WILDBOX_SETTINGS`` (with a ``DATA_URL`` that named identity's port) and
  ``apps/core/utils.py``, which no module read or imported.

The migration tests go back to the schema of 0.11.2 for the two apps, store
what an operator could have stored there, and run the upgrade the image's
entrypoint runs.
"""

import importlib.util
import logging
import uuid

import pytest
from django.apps import apps as django_apps
from django.conf import settings
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder
from django.test import Client
from django.urls import Resolver404, resolve

from tests.unit import team_fixtures as tf

ATTACHMENTS = "vulnerabilities_vulnerabilityattachment"
LOGS = "integrations_integrationlog"
PAYLOADS = ("request_data", "response_data")

DROP_ATTACHMENTS = ("vulnerabilities", "0004_drop_unused_attachments")
BEFORE_ATTACHMENTS = ("vulnerabilities", "0003_resolved_at_follows_status")
DROP_PAYLOADS = ("integrations", "0005_drop_unwritten_log_payloads")
BEFORE_PAYLOADS = ("integrations", "0004_drop_stored_credentials")

#: Part of the payload the tests store; it must not survive the upgrade.
MARKER = "s3cr3t-665"


def _tables():
    with connection.cursor() as cursor:
        return set(connection.introspection.table_names(cursor))


def _columns(table):
    with connection.cursor() as cursor:
        return {
            column.name
            for column in connection.introspection.get_table_description(cursor, table)
        }


def _count(table):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) FROM {connection.ops.quote_name(table)}")
        return cursor.fetchone()[0]


def _database_text():
    chunks = []
    with connection.cursor() as cursor:
        for table in connection.introspection.table_names(cursor):
            cursor.execute(f"SELECT * FROM {connection.ops.quote_name(table)}")
            chunks.extend(repr(row) for row in cursor.fetchall())
    return "\n".join(chunks)


def _applied(migration):
    return migration in MigrationRecorder(connection).applied_migrations()


def _reverse(migration, before):
    """Undo one migration, as ``migrate <app> <previous>`` would.

    Returns the models of the schema before it. The migration's own
    ``unapply`` runs, without the executor around it (see
    test_no_stored_credentials.py for why).
    """
    loader = MigrationLoader(connection)
    state = loader.project_state([before])
    if _applied(migration):
        with connection.schema_editor() as editor:
            loader.get_migration(*migration).unapply(state, editor)
        MigrationRecorder(connection).record_unapplied(*migration)
    return state.apps


def _upgrade():
    """What the image's entrypoint does at start: ``manage.py migrate``."""
    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())


# --- what is gone -------------------------------------------------------------


@pytest.mark.django_db
def test_there_is_no_attachment_model_and_no_table():
    with pytest.raises(LookupError):
        django_apps.get_model("vulnerabilities", "VulnerabilityAttachment")
    assert ATTACHMENTS not in _tables()


@pytest.mark.django_db
def test_the_integration_log_has_no_payload_columns():
    log = django_apps.get_model("integrations", "IntegrationLog")
    assert not set(PAYLOADS) & {field.name for field in log._meta.get_fields()}
    assert not set(PAYLOADS) & _columns(LOGS)


def test_there_is_no_admin_route(settings, monkeypatch):
    for path in ("/admin/", "/admin/login/"):
        with pytest.raises(Resolver404):
            resolve(path)
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    client = Client(raise_request_exception=False)
    assert client.get("/admin/", secure=True).status_code == 404


def test_the_settings_nothing_read_are_gone():
    assert not hasattr(settings, "WILDBOX_SETTINGS")
    assert importlib.util.find_spec("apps.core.utils") is None


# --- the attachment table -----------------------------------------------------


@pytest.fixture
def before_the_drop():
    """The 0.11.2 schema of the attachment table; the current one afterwards."""
    try:
        yield _reverse(DROP_ATTACHMENTS, BEFORE_ATTACHMENTS)
    finally:
        if ATTACHMENTS in _tables():
            with connection.cursor() as cursor:
                cursor.execute(f"DELETE FROM {connection.ops.quote_name(ATTACHMENTS)}")
        _upgrade()


@pytest.mark.django_db(transaction=True)
def test_an_empty_attachment_table_is_dropped(before_the_drop):
    assert ATTACHMENTS in _tables() and _count(ATTACHMENTS) == 0

    _upgrade()

    assert ATTACHMENTS not in _tables()
    assert _applied(DROP_ATTACHMENTS)
    # Applying it again changes nothing and does not fail.
    _upgrade()
    assert ATTACHMENTS not in _tables()


def _attach(old_apps):
    """A row as only a hand, or the ORM in a shell, could have written it."""
    from apps.vulnerabilities.models import Vulnerability

    team = uuid.uuid4()
    vulnerability = tf.make(Vulnerability, team)
    attachment = old_apps.get_model("vulnerabilities", "VulnerabilityAttachment")
    return attachment.objects.create(
        vulnerability_id=vulnerability.pk,
        uploaded_by_id=tf.user(team).pk,
        file="vulnerability_attachments/evidence.txt",
        filename="evidence.txt",
        file_size=1,
        content_type="text/plain",
        description="kept by hand",
    )


@pytest.mark.django_db(transaction=True)
def test_a_table_with_rows_is_refused_and_nothing_is_lost(before_the_drop):
    row = _attach(before_the_drop)

    with pytest.raises(Exception) as refused:
        _upgrade()

    message = str(refused.value)
    assert type(refused.value).__name__ == "AttachmentsExist"
    assert ATTACHMENTS in message and "1 row(s)" in message
    assert "This migration changed nothing" in message and "migrate" in message
    # The table, the row and its values are as they were, and the migration
    # is not recorded: the next start asks again.
    assert ATTACHMENTS in _tables()
    assert not _applied(DROP_ATTACHMENTS)
    kept = type(row).objects.get(pk=row.pk)
    assert (kept.filename, kept.description) == ("evidence.txt", "kept by hand")
    assert kept.file.name == "vulnerability_attachments/evidence.txt"

    # Refused again for as long as the row is there.
    with pytest.raises(Exception):
        _upgrade()
    assert _count(ATTACHMENTS) == 1

    # Once the operator has emptied the table, the same upgrade goes through.
    type(row).objects.all().delete()
    _upgrade()
    assert ATTACHMENTS not in _tables()


@pytest.mark.django_db(transaction=True)
def test_reversing_the_drop_brings_back_an_empty_table(before_the_drop):
    _upgrade()
    assert ATTACHMENTS not in _tables()

    _reverse(DROP_ATTACHMENTS, BEFORE_ATTACHMENTS)

    assert ATTACHMENTS in _tables() and _count(ATTACHMENTS) == 0
    assert {"file", "filename", "vulnerability_id", "uploaded_by_id"} <= _columns(
        ATTACHMENTS
    )


# --- the payload columns ------------------------------------------------------


@pytest.fixture
def before_the_payload_drop():
    """The 0.11.2 schema of the integration log; the current one afterwards."""
    try:
        yield _reverse(DROP_PAYLOADS, BEFORE_PAYLOADS)
    finally:
        _upgrade()


def _log(old_apps):
    """Two log rows, one with payloads written by hand, one without."""
    team = uuid.uuid4()
    system = tf.external_system(team)
    log = old_apps.get_model("integrations", "IntegrationLog")
    log.objects.create(
        system_id=system.pk,
        operation="api_call",
        message="with payloads",
        request_data={"headers": {"Authorization": f"Bearer {MARKER}-request"}},
        response_data={"access_token": f"{MARKER}-response"},
    )
    log.objects.create(system_id=system.pk, operation="sync", message="without")


@pytest.mark.django_db(transaction=True)
def test_the_upgrade_drops_the_payloads_and_keeps_the_log(
    before_the_payload_drop, caplog
):
    assert set(PAYLOADS) <= _columns(LOGS)
    _log(before_the_payload_drop)
    assert _database_text().count(MARKER) == 2

    with caplog.at_level(logging.WARNING):
        _upgrade()

    assert not set(PAYLOADS) & _columns(LOGS)
    assert MARKER not in _database_text()
    log = django_apps.get_model("integrations", "IntegrationLog")
    assert sorted(log.objects.values_list("message", flat=True)) == [
        "with payloads",
        "without",
    ]
    # The operator is told how many rows held one, and no value.
    assert MARKER not in caplog.text
    messages = [record.getMessage() for record in caplog.records]
    for column in PAYLOADS:
        assert any(
            m.startswith("1 integration log row(s)") and column in m for m in messages
        ), (column, messages)

    # Applying it again changes nothing and does not fail.
    _upgrade()
    assert log.objects.count() == 2


@pytest.mark.django_db(transaction=True)
def test_an_upgrade_without_payloads_says_nothing(before_the_payload_drop, caplog):
    team = uuid.uuid4()
    log = before_the_payload_drop.get_model("integrations", "IntegrationLog")
    log.objects.create(
        system_id=tf.external_system(team).pk, operation="sync", message="without"
    )

    with caplog.at_level(logging.WARNING):
        _upgrade()

    assert not [r for r in caplog.records if "integration log" in r.getMessage()]
    assert _count(LOGS) == 1


@pytest.mark.django_db(transaction=True)
def test_reversing_the_payload_drop_restores_nothing(before_the_payload_drop):
    _log(before_the_payload_drop)
    _upgrade()

    old_apps = _reverse(DROP_PAYLOADS, BEFORE_PAYLOADS)

    assert set(PAYLOADS) <= _columns(LOGS)
    log = old_apps.get_model("integrations", "IntegrationLog")
    assert list(log.objects.values_list(*PAYLOADS)) == [({}, {}), ({}, {})]
    assert MARKER not in _database_text()
