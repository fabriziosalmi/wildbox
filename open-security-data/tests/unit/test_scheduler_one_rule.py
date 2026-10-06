"""The scheduler has one rule for the sources it runs (#778).

At start it left out an enabled source whose status was ``error``. The
periodic reload, which runs every ten minutes, did not: it scheduled the same
source to run thirty seconds later. A source in error was therefore collected
after every restart all the same, up to ten minutes later than the others,
and whether the scheduler was running a given source depended on how long
the scheduler had been up.

The rule is the reload's, which is also what the scheduler does with a
source that fails while it runs: it keeps the task and tries again at the
source's interval, until the error count disables the source.
"""

import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import CIDR, INET, UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.collectors import sources as source_collectors  # noqa: E402,F401
from app.models import CollectionRun, Source  # noqa: E402
from app.scheduler.main import CollectionScheduler  # noqa: E402


@compiles(UUID, "sqlite")
def _uuid_on_sqlite(_type, _compiler, **_kw):
    return "CHAR(32)"


@compiles(INET, "sqlite")
@compiles(CIDR, "sqlite")
def _address_on_sqlite(_type, _compiler, **_kw):
    return "VARCHAR(64)"


@pytest.fixture
def db(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Source.metadata.create_all(
        engine, tables=[Source.__table__, CollectionRun.__table__]
    )
    factory = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr("app.scheduler.main.get_db_session", factory)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def a_source(name, status="active", enabled=True, source_type="feodo_tracker", **more):
    return Source(
        id=uuid.uuid4(),
        name=name,
        source_type=source_type,
        config={},
        headers={},
        rate_limit=100,
        rate_limit_window=60,
        timeout=30,
        collection_interval=3600,
        enabled=enabled,
        status=status,
        **more,
    )


# Every status a source's row can hold (app/models.py, the scheduler and
# manage.py write them), enabled; then what is never scheduled.
STATUSES = ["active", "error", "rate_limited", "inactive"]


@pytest.fixture
def sources(db):
    for status in STATUSES:
        db.add(a_source(f"enabled, {status}", status=status))
    db.add(a_source("disabled after ten errors", status="error", enabled=False))
    db.add(a_source("disabled by the operator", status="inactive", enabled=False))
    db.add(a_source("no collector for it", status="error", source_type="json"))
    db.commit()
    return db


def _scheduled(scheduler):
    return sorted(task.source.name for task in scheduler.tasks.values())


def _at_start():
    scheduler = CollectionScheduler()
    asyncio.run(scheduler._load_sources())
    return scheduler


def _at_reload():
    scheduler = CollectionScheduler()
    asyncio.run(scheduler._reload_sources())
    return scheduler


EVERY_ENABLED_SOURCE = sorted(f"enabled, {status}" for status in STATUSES)


def test_the_start_schedules_every_enabled_source_it_can_collect(sources):
    assert _scheduled(_at_start()) == EVERY_ENABLED_SOURCE


def test_the_reload_schedules_the_same_sources(sources):
    assert _scheduled(_at_reload()) == EVERY_ENABLED_SOURCE


def test_a_source_in_error_is_scheduled_at_start_like_any_other(db):
    """What the start left out: main scheduled the first of these alone."""
    db.add(a_source("answering", status="active"))
    db.add(a_source("failed last time", status="error", last_error="HTTP 503"))
    db.commit()

    scheduler = _at_start()

    assert _scheduled(scheduler) == ["answering", "failed last time"]
    # Scheduling it does not touch its row: the error stays until a
    # collection succeeds.
    db.expire_all()
    row = db.query(Source).filter_by(name="failed last time").one()
    assert (row.status, row.last_error, row.enabled) == ("error", "HTTP 503", True)


def test_a_reload_after_the_start_changes_nothing(sources):
    """The two used to disagree, so the first reload added the sources in
    error to a scheduler that had started without them."""
    scheduler = _at_start()
    before = {key: task.next_run for key, task in scheduler.tasks.items()}

    asyncio.run(scheduler._reload_sources())

    assert _scheduled(scheduler) == EVERY_ENABLED_SOURCE
    assert {key: task.next_run for key, task in scheduler.tasks.items()} == before


@pytest.mark.parametrize("load", [_at_start, _at_reload], ids=["start", "reload"])
def test_neither_schedules_a_disabled_source_nor_one_without_a_collector(sources, load):
    scheduled = _scheduled(load())

    assert "disabled after ten errors" not in scheduled
    assert "disabled by the operator" not in scheduled
    assert "no collector for it" not in scheduled
    # The one nothing can collect is disabled, with the reason (#755).
    sources.expire_all()
    row = sources.query(Source).filter_by(name="no collector for it").one()
    assert (row.enabled, row.status) == (False, "inactive")
    assert row.last_error == "No collector for source type 'json'"


def test_a_source_never_collected_is_first_run_within_five_minutes_at_start(db):
    """In error or not: the first runs are spread, not all at once."""
    db.add(a_source("new and failing", status="error"))
    db.add(a_source("new"))
    db.commit()
    before = datetime.now(timezone.utc)

    scheduler = _at_start()

    assert len(scheduler.tasks) == 2
    for task in scheduler.tasks.values():
        assert before <= task.next_run <= before + timedelta(seconds=305)


def test_a_source_the_scheduler_disabled_for_its_errors_leaves_at_the_reload(db):
    """What stops a failing source: its error count, at the tenth."""
    db.add(a_source("failing", status="error", error_count=9))
    db.commit()
    scheduler = _at_start()
    (task,) = scheduler.tasks.values()

    asyncio.run(scheduler._handle_collection_error(task.source, "HTTP 503"))
    asyncio.run(scheduler._reload_sources())

    assert scheduler.tasks == {}
    db.expire_all()
    row = db.query(Source).one()
    assert (row.enabled, row.error_count, row.status) == (False, 10, "error")
    assert _scheduled(_at_start()) == []
