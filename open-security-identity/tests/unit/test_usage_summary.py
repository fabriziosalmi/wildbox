"""The admin analytics report counts, never estimates (#570).

GET /analytics/admin/usage-summary returned ``api_requests_today`` as the
number of API keys used in the last day times 75, and
GET /analytics/admin/system-stats returned ``estimated_requests_today`` and
``estimated_requests_week`` the same way (x 50, x 200). identity does not see
the requests -- the gateway serves them -- so it has no count to give, and
the fields are gone. The database is a stub that answers every count with
the same number, so this needs neither PostgreSQL nor Redis.
"""

import asyncio
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api_v1.endpoints import analytics  # noqa: E402

COUNT = 4
SUPERUSER = SimpleNamespace(is_superuser=True)


class _Result:
    def scalar(self):
        return COUNT

    def __iter__(self):
        return iter([])


class _Db:
    async def execute(self, *_args, **_kwargs):
        return _Result()


def _usage_summary(user=SUPERUSER):
    return asyncio.run(analytics.get_usage_summary(current_user=user, db=_Db()))


def _system_stats():
    return asyncio.run(
        analytics.get_system_analytics(current_user=SUPERUSER, db=_Db(), days=30)
    )


def test_usage_summary_reports_only_counts():
    summary = _usage_summary()["summary"]
    assert set(summary) == {
        "total_users",
        "active_users",
        "total_teams",
        "api_keys_active",
    }
    assert "api_requests_today" not in summary


def test_usage_summary_values_come_from_the_database():
    summary = _usage_summary()["summary"]
    assert summary["api_keys_active"] == COUNT
    assert summary["total_users"] == COUNT
    # The removed estimate was api_keys_active * 75; no value may be one.
    assert COUNT * 75 not in summary.values()


def test_usage_summary_still_requires_a_superuser():
    with pytest.raises(HTTPException) as exc:
        _usage_summary(SimpleNamespace(is_superuser=False))
    assert exc.value.status_code == 403


def test_system_stats_report_no_request_estimates():
    api_usage = _system_stats()["api_usage"]
    assert set(api_usage) == {"total_keys", "active_keys", "keys_used_today"}
    assert api_usage["keys_used_today"] == COUNT
