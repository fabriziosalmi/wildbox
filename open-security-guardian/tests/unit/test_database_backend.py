"""The suite runs on the database it is said to run on (#724).

guardian is deployed on PostgreSQL. Its unit tests run on in-memory SQLite by
default (``guardian/settings_test.py``), and CI also runs them on PostgreSQL
(the ``guardian-postgres-tests`` job of ``.github/workflows/test.yml``), by
setting ``DATABASE_URL``. If that variable stopped reaching the settings, the
second run would be SQLite again and as green as the first.

The job therefore names the vendor it expects in
``GUARDIAN_REQUIRE_DATABASE_VENDOR``, and this fails when the connection is
another one. Where the variable is not set, nothing is required.
"""

import os
import re
from pathlib import Path

import pytest
from django.db import connection

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"
VARIABLE = "GUARDIAN_REQUIRE_DATABASE_VENDOR"


def test_the_database_is_the_one_the_run_asked_for():
    required = os.environ.get(VARIABLE)
    if not required:
        pytest.skip(f"{VARIABLE} is not set: any database will do")
    assert connection.vendor == required


def test_on_postgresql_no_lookup_is_missing():
    """What the SQLite run has to skip, the PostgreSQL run must not."""
    if connection.vendor != "postgresql":
        pytest.skip("only PostgreSQL is required to have every lookup")
    assert connection.features.supports_json_field_contains


@pytest.mark.skipif(not WORKFLOW.exists(), reason="needs the repository checkout")
def test_ci_runs_the_suite_on_postgresql_and_says_so():
    job = WORKFLOW.read_text(encoding="utf-8").split("  guardian-postgres-tests:", 1)
    assert len(job) == 2, "the PostgreSQL job is gone from test.yml"
    body = job[1].split("\n  shared-package-tests:", 1)[0]

    assert f"{VARIABLE}: postgresql" in body
    assert "DATABASE_URL=postgres://" in body
    assert "pytest tests/unit/" in body
    # The same major version as the stack's database.
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    # The tag, with or without the digest it is pinned by (#726).
    assert re.search(r"image: postgres:15(@sha256:[0-9a-f]{64})?\n", compose)
    assert "postgres:15 " in body
