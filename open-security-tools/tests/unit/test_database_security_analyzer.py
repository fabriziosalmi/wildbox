"""Unit tests for the Database Security Analyzer.

The tool connects to a live PostgreSQL/MySQL server; these tests replace the
connection with a fake cursor that returns captured real query results, so
they run offline. The suite locks in that every reported value comes from a
query — the previous version fabricated the whole assessment
(_test_connection was random.random() > 0.1, the version was random.choice,
users/privileges/encryption were random) — and that unsupported engines and
failed connections are reported honestly rather than faked.
"""
import asyncio
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

APP_DIR = Path(__file__).resolve().parents[2] / "app"
TOOL_DIR = APP_DIR / "tools" / "database_security_analyzer"

sys.path.insert(0, str(APP_DIR))


def _load(name, path, extra_modules=None):
    """Load a tool module under a unique name (see test_ct_log_scanner)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    injected = list((extra_modules or {}).items())
    for key, value in injected:
        sys.modules[key] = value
    try:
        spec.loader.exec_module(module)
    finally:
        for key, _ in injected:
            sys.modules.pop(key, None)
    return module


_std = _load("db_standardized_schemas", APP_DIR / "standardized_schemas.py")
_schemas = _load("db_schemas", TOOL_DIR / "schemas.py", {"standardized_schemas": _std})
dsa = _load("db_main", TOOL_DIR / "main.py", {"schemas": _schemas})


class FakeCursor:
    """Returns a captured result per SQL substring; asserts on unknowns."""

    def __init__(self, responses):
        self._responses = responses
        self._result = []

    def execute(self, sql):
        for needle, rows in self._responses.items():
            if needle in sql:
                self._result = rows
                return
        raise AssertionError(f"unexpected query: {sql[:60]}")

    def fetchall(self):
        return list(self._result)

    def close(self):
        pass


class FakeConn:
    def __init__(self, responses):
        self._responses = responses

    def cursor(self):
        return FakeCursor(self._responses)

    def close(self):
        pass


def _patch_connection(monkeypatch, responses):
    conn = FakeConn(responses)
    monkeypatch.setattr(dsa.DatabaseSecurityAnalyzer, "_connect_postgres", staticmethod(lambda inp: conn))
    monkeypatch.setattr(dsa.DatabaseSecurityAnalyzer, "_connect_mysql", staticmethod(lambda inp: conn))


def run(**overrides):
    params = dict(database_type="postgresql", host="db.example", port=5432, username="reader")
    params.update(overrides)
    return asyncio.run(dsa.execute_tool(_schemas.DatabaseSecurityAnalyzerInput(**params)))


# Captured shapes from the real EBI public servers.
PG_RESPONSES = {
    "pg_settings": [
        ("ssl", "off"),
        ("password_encryption", "md5"),
        ("log_connections", "off"),
        ("logging_collector", "on"),
        ("log_statement", "none"),
        ("listen_addresses", "*"),
    ],
    "SHOW server_version": [("16.11",)],
    "pg_roles": [
        ("postgres", True, True, None),
        ("reader", False, True, None),
        ("backup", False, False, None),
    ],
}

MYSQL_RESPONSES = {
    "have_ssl": [("have_ssl", "YES")],
    "require_secure_transport": [("require_secure_transport", "OFF")],
    "local_infile": [("local_infile", "ON")],
    "skip_name_resolve": [("skip_name_resolve", "ON")],
    "general_log": [("general_log", "OFF")],
    "SELECT VERSION()": [("8.0.32-24",)],
    "mysql.user": [
        ("root", "localhost", "Y", "Y", 0),
        ("app", "%", "N", "Y", 0),
        ("anon", "%", "N", "Y", 1),      # no password + wildcard host
    ],
}


class TestPostgres:
    def test_reads_real_settings_and_roles(self, monkeypatch):
        _patch_connection(monkeypatch, PG_RESPONSES)
        out = run(database_type="postgresql")
        assert out.success is True
        assert out.database_info["version"] == "16.11"
        assert out.encryption_status.data_in_transit_encrypted is False   # ssl=off
        assert len(out.database_users) == 3
        # A logged-in superuser is flagged.
        postgres = next(u for u in out.database_users if u.username == "postgres")
        assert postgres.admin_privileges is True
        assert postgres.security_issues

    def test_flags_ssl_off_and_md5(self, monkeypatch):
        _patch_connection(monkeypatch, PG_RESPONSES)
        params = {c.parameter for c in run(database_type="postgresql").configuration_issues}
        assert "ssl" in params
        assert "password_encryption" in params

    def test_at_rest_encryption_is_reported_not_guessed(self, monkeypatch):
        _patch_connection(monkeypatch, PG_RESPONSES)
        out = run(database_type="postgresql")
        # Not observable over SQL -> reported False, and the summary says so.
        assert out.encryption_status.data_at_rest_encrypted is False
        assert "not observable" in out.scan_summary["note"]


class TestMySQL:
    def test_reads_real_variables(self, monkeypatch):
        _patch_connection(monkeypatch, MYSQL_RESPONSES)
        out = run(database_type="mysql", port=3306)
        assert out.success is True
        assert out.database_info["version"] == "8.0.32-24"
        # have_ssl YES but require_secure OFF -> not enforced.
        assert out.encryption_status.data_in_transit_encrypted is False

    def test_flags_dangerous_accounts(self, monkeypatch):
        _patch_connection(monkeypatch, MYSQL_RESPONSES)
        out = run(database_type="mysql", port=3306)
        anon = next(u for u in out.database_users if u.username == "anon")
        assert anon.password_policy_compliant is False
        assert any("no password" in i.lower() for i in anon.security_issues)
        # A passwordless, wildcard-host account is a Critical vulnerability.
        assert any(v.severity == "Critical" for v in out.vulnerabilities)

    def test_flags_local_infile(self, monkeypatch):
        _patch_connection(monkeypatch, MYSQL_RESPONSES)
        params = {c.parameter for c in run(database_type="mysql", port=3306).configuration_issues}
        assert "local_infile" in params


class TestHonestDegradation:
    def test_unsupported_engine_is_refused(self):
        out = run(database_type="oracle", port=1521)
        assert out.success is False
        assert "not supported" in out.summary

    def test_connection_failure_is_not_a_passing_scan(self, monkeypatch):
        def boom(inp):
            raise OSError("connection refused")

        monkeypatch.setattr(dsa.DatabaseSecurityAnalyzer, "_connect_postgres", staticmethod(boom))
        out = run(database_type="postgresql")
        assert out.success is False
        assert out.connection_successful is False
        assert out.database_users == []

    def test_missing_credentials_are_rejected(self):
        out = asyncio.run(
            dsa.execute_tool(_schemas.DatabaseSecurityAnalyzerInput(
                database_type="mysql", host="", port=3306))
        )
        assert out.success is False
        assert "host and username" in out.summary
