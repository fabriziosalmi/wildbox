"""What the scheduler does with a collection that fails (#788).

A collection can end four ways: its collector returns a result (completed,
rate limited, failed, timed out), the scheduler's own time limit ends it, or
it raises. The scheduler's handling of the last two, and of a database that
is away, had been left as it was when the collectors' own handling was
rewritten (#755, #778).

The scheduler here is the real one, on the SQLite database of
test_scheduler_one_rule.py. The collector is a stand-in that ends the way the
test says: what is under test is what the scheduler does with each ending.
"""

import asyncio
import logging
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError, InterfaceError, OperationalError
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import manage  # noqa: E402
import throwaway_postgres  # noqa: E402
from app import collectors  # noqa: E402
from app.collectors import (  # noqa: E402
    BaseCollector,
    CollectionResult,
    CollectionStatus,
    CollectorRegistry,
)
from app.models import Base, CollectionRun, Source  # noqa: E402
from app.scheduler import main as scheduler_main  # noqa: E402
from app.scheduler.main import CollectionScheduler  # noqa: E402
from test_scheduler_one_rule import a_source, db  # noqa: E402,F401

# A feed's URL with its key in the path, as URLVoid's has it, and what an
# HTTP client's error says about a request it could not make.
KEY = "k3y-0f-th3-f33d"
FEED_URL = f"https://feed.example/1000/{KEY}/host/evil.example"
ERROR_TEXT = f"Cannot connect to host feed.example:443 ssl:default [{FEED_URL}]"


class Ends:
    """A collector whose collections end as the test says, in order: an
    exception is raised, a status is returned in a result."""

    def __init__(self, monkeypatch, *endings):
        self.endings = list(endings)
        self.ran = 0
        monkeypatch.setattr(CollectorRegistry, "get_collector", lambda source: self)

    async def run_collection(self):
        ending = self.endings[min(self.ran, len(self.endings) - 1)]
        self.ran += 1
        if isinstance(ending, BaseException):
            raise ending
        if ending == "never":
            await asyncio.Event().wait()
        if isinstance(ending, CollectionResult):
            return ending
        return CollectionResult(
            status=CollectionStatus(ending),
            error_message=None if ending == "completed" else f"{ending} (HTTP 503)",
        )


@pytest.fixture
def one(db):  # noqa: F811 - the fixture of test_scheduler_one_rule.py
    """A scheduler with one source, loaded as at start; its task, and a way
    to read the source's row."""
    source = a_source("feed")
    # The seconds the scheduler gives one collection.
    source.timeout = 1
    db.add(source)
    db.commit()
    scheduler = CollectionScheduler()
    asyncio.run(scheduler._load_sources())
    (task,) = scheduler.tasks.values()

    def row():
        db.expire_all()
        return db.query(Source).one()

    return scheduler, task, row


def _collect(scheduler, task, times=1):
    async def run():
        for _ in range(times):
            await scheduler._run_collection(task)

    asyncio.run(run())


def _errors(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.name == scheduler_main.__name__ and record.levelno >= logging.ERROR
    ]


# --- What is stored about an error that reaches the scheduler ---------------------


@pytest.mark.parametrize(
    "error, stored",
    [
        (ConnectionError(ERROR_TEXT), "ConnectionError"),
        (ValueError(ERROR_TEXT), "ValueError"),
        (KeyError(ERROR_TEXT), "KeyError"),
        (TypeError(ERROR_TEXT), "TypeError"),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_the_class_of_the_error_is_stored_and_logged_not_its_text(
    one, monkeypatch, caplog, error, stored
):
    scheduler, task, row = one
    Ends(monkeypatch, error)

    with caplog.at_level(logging.ERROR, logger=scheduler_main.__name__):
        _collect(scheduler, task)

    # main: the text, with the feed's URL and the key in it, in the row
    # `manage.py sources list` prints, in the scheduler's status and in the log.
    assert row().last_error == stored
    assert task.last_error == stored
    assert scheduler.get_status()["errors"] == {str(task.source.id): stored}
    (said,) = _errors(caplog)
    assert said.startswith(f"Collection error for source feed: {stored}\n")
    # The frames, for the operator, and not the exception at their end.
    assert "run_collection" in said
    for text in (said, caplog.text, str(scheduler.get_status())):
        assert KEY not in text and "feed.example" not in text
    assert row().status == "error"


def test_an_http_error_keeps_its_status(one, monkeypatch):
    scheduler, task, row = one

    class Refused(ConnectionError):
        status = 403

    Ends(monkeypatch, Refused(ERROR_TEXT))

    _collect(scheduler, task)

    assert row().last_error == task.last_error == "Refused (HTTP 403)"


def test_a_collection_the_scheduler_times_out_is_stored_as_before(one, monkeypatch):
    scheduler, task, row = one
    Ends(monkeypatch, "never")

    _collect(scheduler, task)

    assert row().last_error == task.last_error == "Collection timeout"


# --- Errors that are none of the five builtins --------------------------------------
# The loop, a collection and the reload each caught ValueError, KeyError,
# TypeError, ConnectionError and TimeoutError. Run under a PostgreSQL that
# was stopped and started again, the scheduler of main did this: a collection
# that asked the database meanwhile failed without a line in the log, eight
# times in eight seconds, and the first reload of the sources ended the
# process, with status 1.

# What PostgreSQL says to a client while it restarts, and what a driver puts
# in front of it: with the address of the server.
SERVER_TEXT = (
    'connection to server at "postgres" (172.18.0.5), port 5432 failed: FATAL:  '
    "the database system is shutting down"
)


def _database_error():
    return OperationalError("SELECT 1", {}, Exception(SERVER_TEXT))


@pytest.mark.parametrize(
    "error, said",
    [
        (_database_error(), "OperationalError (Exception)"),
        (RuntimeError(ERROR_TEXT), "RuntimeError"),
        (OSError(ERROR_TEXT), "OSError"),
    ],
    ids=["a database error", "RuntimeError", "OSError"],
)
def test_a_collection_that_raises_any_error_is_said_once_by_its_class(
    one, monkeypatch, caplog, error, said
):
    scheduler, task, row = one
    Ends(monkeypatch, error)

    with caplog.at_level(logging.ERROR, logger=scheduler_main.__name__):
        _collect(scheduler, task)

    # main: nothing. The error left _run_collection, and asyncio.gather
    # kept it as a result nobody read.
    (line,) = _errors(caplog)
    assert line.startswith(f"Collection error for source feed: {said}\n")
    assert KEY not in caplog.text and "172.18.0.5" not in caplog.text
    assert "shutting down" not in caplog.text
    assert task.last_error == row().last_error == said
    assert task.running is False


def test_a_failure_the_database_does_not_take_is_said_and_the_scheduler_goes_on(
    one, monkeypatch, caplog
):
    """The collection failed for the database, and so does the note of it."""
    scheduler, task, row = one
    Ends(monkeypatch, _database_error())

    def no_session():
        raise _database_error()

    with caplog.at_level(logging.ERROR, logger=scheduler_main.__name__):
        monkeypatch.setattr(scheduler_main, "get_db_session", no_session)
        _collect(scheduler, task)
        monkeypatch.undo()

    first, second = _errors(caplog)
    assert first.startswith("Collection error for source feed: OperationalError")
    assert second == (
        "The failed collection of source feed could not be recorded: "
        "OperationalError (Exception)"
    )
    assert "shutting down" not in caplog.text
    assert task.running is False


class Pace:
    """The scheduler's loop at the pace of a test: a tick is a few
    milliseconds, and a reload is due when the test says."""

    def __init__(self, monkeypatch, scheduler, reload=False):
        monkeypatch.setattr(scheduler_main, "TICK_SECONDS", 0.005)
        monkeypatch.setattr(scheduler_main, "RETRY_SECONDS", 0.005)
        monkeypatch.setattr(scheduler, "_reload_due", lambda current_time: reload)
        self.scheduler = scheduler

    async def until(self, condition):
        deadline = asyncio.get_running_loop().time() + 20
        while not condition():
            assert asyncio.get_running_loop().time() < deadline, "timed out"
            assert not self.loop.done(), "the scheduler's loop ended"
            await asyncio.sleep(0.005)

    def run(self, scenario):
        async def main():
            self.scheduler.running = True
            self.loop = asyncio.ensure_future(self.scheduler._scheduler_loop())
            try:
                await scenario()
            finally:
                await self.scheduler.stop()
                await asyncio.wait_for(
                    asyncio.gather(self.loop, return_exceptions=True), 10
                )
            return self.loop

        return asyncio.run(main())


def test_the_loop_outlives_a_reload_the_database_does_not_answer(
    one, monkeypatch, caplog
):
    scheduler, task, row = one
    Ends(monkeypatch, "completed")
    task.next_run = datetime.now(timezone.utc) + timedelta(days=1)
    pace = Pace(monkeypatch, scheduler, reload=True)
    sessions = scheduler_main.get_db_session
    asked = []

    def away_at_first():
        asked.append(1)
        if len(asked) <= 3:
            raise _database_error()
        return sessions()

    monkeypatch.setattr(scheduler_main, "get_db_session", away_at_first)

    async def scenario():
        # Three reloads fail, and the fourth is made, and answered.
        await pace.until(lambda: len(asked) >= 5)

    with caplog.at_level(logging.ERROR, logger=scheduler_main.__name__):
        loop = pace.run(scenario)

    # main: the first of them ended the loop, and the process with it.
    assert loop.exception() is None
    said = _errors(caplog)
    assert len(said) == 3
    for line in said:
        assert line.startswith(
            "Error reloading sources: OperationalError (Exception)\n"
        )
        assert "_reload_sources" in line
    assert "shutting down" not in caplog.text
    # The tasks are the ones it had: a reload that fails removes none.
    assert list(scheduler.tasks.values()) == [task]


def test_the_loop_outlives_an_error_of_its_own_pass(one, monkeypatch, caplog):
    """Whatever raises in the pass itself, a database error among them."""
    scheduler, task, row = one
    Ends(monkeypatch, "completed")
    task.next_run = datetime.now(timezone.utc) + timedelta(days=1)
    pace = Pace(monkeypatch, scheduler, reload=True)
    reloads = []

    async def reload():
        reloads.append(1)
        if len(reloads) <= 2:
            raise _database_error()

    monkeypatch.setattr(scheduler, "_reload_sources", reload)

    async def scenario():
        await pace.until(lambda: len(reloads) >= 4)

    with caplog.at_level(logging.ERROR, logger=scheduler_main.__name__):
        loop = pace.run(scenario)

    assert loop.exception() is None
    said = _errors(caplog)
    assert len(said) == 2
    assert said[0].startswith("Error in scheduler loop: OperationalError (Exception)\n")
    assert "shutting down" not in caplog.text


def test_an_error_that_leaves_a_collection_all_the_same_is_said_by_the_loop(
    one, monkeypatch, caplog
):
    """What asyncio.gather keeps as a result is read: once, with the name
    of the source, and the other collections of the pass are not its."""
    scheduler, task, row = one
    task.next_run = datetime.now(timezone.utc) - timedelta(seconds=1)
    pace = Pace(monkeypatch, scheduler)
    ran = []

    async def run_collection(due):
        ran.append(due)
        due.next_run = datetime.now(timezone.utc) + timedelta(days=1)
        raise RuntimeError(ERROR_TEXT)

    monkeypatch.setattr(scheduler, "_run_collection", run_collection)

    async def scenario():
        await pace.until(lambda: ran)
        for _ in range(20):
            await asyncio.sleep(0.005)

    with caplog.at_level(logging.ERROR, logger=scheduler_main.__name__):
        loop = pace.run(scenario)

    assert loop.exception() is None
    (line,) = _errors(caplog)
    assert line.startswith("Collection error for source feed: RuntimeError\n")
    assert KEY not in caplog.text


def test_a_stop_asked_for_while_the_loop_waits_after_an_error_is_obeyed(
    one, monkeypatch
):
    scheduler, task, row = one
    task.next_run = datetime.now(timezone.utc) + timedelta(days=1)
    pace = Pace(monkeypatch, scheduler, reload=True)
    monkeypatch.setattr(scheduler_main, "RETRY_SECONDS", 3600)
    failed = []

    async def reload():
        failed.append(1)
        raise _database_error()

    monkeypatch.setattr(scheduler, "_reload_sources", reload)

    async def scenario():
        await pace.until(lambda: failed)
        # Twenty ticks of the loop: it is waiting, and makes no other pass.
        await asyncio.sleep(0.1)
        assert len(failed) == 1

    # main: asyncio.sleep(60), whatever was asked meanwhile.
    loop = pace.run(scenario)

    assert loop.exception() is None and len(failed) == 1


# --- One rule for the count (#788) ---------------------------------------------------
# Ten collections in a row that fail, whichever way, disable a source; one
# that completes sets the count back to 0. There were two rules: a collection
# that raised or timed out was counted and disabled its source at ten, one
# whose collector returned "failed" was counted and disabled nothing, and no
# success ever set the count back.

TEN = scheduler_main.MAX_FAILURES_IN_A_ROW


def _state(row):
    source = row()
    return source.error_count, source.enabled, source.status


def _fast_timeout(task):
    """The seconds the scheduler gives a collection, for the endings that
    never return."""
    task.source.timeout = 0.01


EVERY_WAY_TO_FAIL = {
    "the collector returns failed": "failed",
    "the collector returns timeout": "timeout",
    "the scheduler's time limit": "never",
    "it raises a builtin error": ValueError(ERROR_TEXT),
    "it raises any other error": RuntimeError(ERROR_TEXT),
}


def test_the_rule_is_ten():
    assert TEN == 10


@pytest.mark.parametrize("way", list(EVERY_WAY_TO_FAIL))
def test_ten_failures_in_a_row_disable_a_source_whichever_way_it_fails(
    one, monkeypatch, caplog, way
):
    scheduler, task, row = one
    _fast_timeout(task)
    Ends(monkeypatch, EVERY_WAY_TO_FAIL[way])

    _collect(scheduler, task, times=TEN - 1)
    assert _state(row) == (TEN - 1, True, "error")

    with caplog.at_level(logging.WARNING, logger=scheduler_main.__name__):
        _collect(scheduler, task)

    # main, for the first two ways: (10, True, "error"), and so on for ever.
    assert _state(row) == (TEN, False, "error")
    assert "Disabling source feed: its last 10 collections have failed" in [
        record.getMessage() for record in caplog.records
    ]
    # And a disabled source leaves the schedule at the next reload.
    asyncio.run(scheduler._reload_sources())
    assert scheduler.tasks == {}


def test_the_ways_to_fail_count_together(one, monkeypatch):
    scheduler, task, row = one
    _fast_timeout(task)
    ways = list(EVERY_WAY_TO_FAIL.values())
    Ends(monkeypatch, *(ways[index % len(ways)] for index in range(TEN)))

    _collect(scheduler, task, times=TEN - 1)
    assert _state(row) == (TEN - 1, True, "error")
    _collect(scheduler, task)

    assert _state(row) == (TEN, False, "error")


def test_a_collection_that_completes_sets_the_count_back(one, monkeypatch):
    scheduler, task, row = one
    endings = ["failed"] * (TEN - 1) + ["completed"] + ["failed"] * TEN
    Ends(monkeypatch, *endings)

    _collect(scheduler, task, times=TEN - 1)
    assert _state(row) == (TEN - 1, True, "error")

    _collect(scheduler, task)
    # main: (9, True, "active"), and the next failure was "the tenth".
    assert _state(row) == (0, True, "active")
    assert row().last_error is None

    # Nine more do not disable it: they are nine in a row, not eighteen.
    _collect(scheduler, task, times=TEN - 1)
    assert _state(row) == (TEN - 1, True, "error")
    _collect(scheduler, task)
    assert _state(row) == (TEN, False, "error")


def test_a_source_that_fails_every_other_time_is_never_disabled(one, monkeypatch):
    scheduler, task, row = one
    Ends(monkeypatch, *(["failed", "completed"] * 15))

    _collect(scheduler, task, times=29)

    # main: fifteen errors counted, and nothing done about them.
    assert _state(row) == (1, True, "error")
    _collect(scheduler, task)
    assert _state(row) == (0, True, "active")


def test_a_rate_limited_collection_is_neither_a_failure_nor_a_success(one, monkeypatch):
    scheduler, task, row = one
    Ends(monkeypatch, *(["failed"] * 5 + ["rate_limited"] + ["failed"] * 5))

    _collect(scheduler, task, times=5)
    assert _state(row) == (5, True, "error")
    _collect(scheduler, task)
    assert _state(row) == (5, True, "rate_limited")
    _collect(scheduler, task, times=4)
    assert _state(row) == (9, True, "error")
    _collect(scheduler, task)
    assert _state(row) == (TEN, False, "error")


def _failed_on(exception_type):
    return CollectionResult(
        status=CollectionStatus.FAILED,
        error_message=exception_type,
        error_details={"exception_type": exception_type},
    )


@pytest.mark.parametrize(
    "ending",
    [
        _failed_on("OperationalError"),
        _failed_on("InterfaceError"),
        OperationalError("SELECT 1", {}, Exception(SERVER_TEXT)),
        InterfaceError("SELECT 1", {}, Exception(SERVER_TEXT)),
    ],
    ids=["returned", "returned, interface", "raised", "raised, interface"],
)
def test_a_database_that_is_away_is_not_the_sources_failure(one, monkeypatch, ending):
    """The data service's own database dropping connections for a while
    must not disable every source it has."""
    scheduler, task, row = one
    Ends(monkeypatch, "failed", "failed", ending)

    _collect(scheduler, task, times=2)
    assert _state(row) == (2, True, "error")
    _collect(scheduler, task, times=2 * TEN)

    # Said with the source, and not counted against it.
    assert _state(row) == (2, True, "error")
    assert row().last_error.startswith(("OperationalError", "InterfaceError"))


@pytest.mark.parametrize(
    "ending",
    [
        _failed_on("IntegrityError"),
        IntegrityError("INSERT", {}, Exception("duplicate key")),
    ],
    ids=["returned", "raised"],
)
def test_a_database_that_refuses_what_a_source_brings_is_the_sources_failure(
    one, monkeypatch, ending
):
    scheduler, task, row = one
    Ends(monkeypatch, ending)

    _collect(scheduler, task, times=TEN)

    assert _state(row) == (TEN, False, "error")


def test_a_source_an_operator_enables_starts_its_count_again(one, monkeypatch):
    scheduler, task, row = one
    Ends(monkeypatch, "failed")
    _collect(scheduler, task, times=TEN)
    assert _state(row) == (TEN, False, "error")
    monkeypatch.setattr(manage, "get_db_session", scheduler_main.get_db_session)

    assert manage.enable_source("feed") is True

    # main: (10, True, "active"), disabled again by its first failure.
    assert _state(row) == (0, True, "active")
    _collect(scheduler, task)
    assert _state(row) == (1, True, "error")


# The count a release before this one left: every failure the source ever
# had. The runs are on record, newest first here.
@pytest.mark.parametrize(
    "counted, runs, corrected",
    [
        # Failed nine times in a year, the last time yesterday.
        (9, ["failed", "completed", "completed", "failed"], 1),
        (37, ["completed", "failed", "failed"], 0),
        (37, ["timeout", "failed", "rate_limited", "completed", "failed"], 2),
        # Nothing the record contradicts: left as it is.
        (37, ["failed"] * 10, 37),
        (37, ["failed"] * 12 + ["completed"], 37),
        (4, [], 4),
        (1, ["failed", "failed", "completed"], 1),
        (0, ["failed", "completed"], 0),
    ],
)
def test_a_count_from_an_earlier_release_is_held_to_the_record_of_runs_at_start(
    db, counted, runs, corrected  # noqa: F811
):
    source = a_source("feed", error_count=counted, status="error")
    db.add(source)
    now = datetime.now(timezone.utc)
    for age, status in enumerate(runs):
        db.add(
            CollectionRun(
                source_id=source.id,
                status=status,
                started_at=now - timedelta(hours=age + 1),
            )
        )
    db.commit()

    scheduler = CollectionScheduler()
    asyncio.run(scheduler._load_sources())

    db.expire_all()
    assert db.query(Source).one().error_count == corrected
    assert len(scheduler.tasks) == 1


def test_such_a_source_outlives_its_next_failure(db, monkeypatch):  # noqa: F811
    """What the correction is for: nine failures in a year and one more."""
    source = a_source("feed", error_count=9, status="active")
    db.add(source)
    now = datetime.now(timezone.utc)
    for age, status in enumerate(["completed", "failed", "completed"]):
        db.add(
            CollectionRun(
                source_id=source.id,
                status=status,
                started_at=now - timedelta(hours=age + 1),
            )
        )
    db.commit()
    scheduler = CollectionScheduler()
    asyncio.run(scheduler._load_sources())
    (task,) = scheduler.tasks.values()
    Ends(monkeypatch, "failed")

    asyncio.run(scheduler._run_collection(task))

    db.expire_all()
    row = db.query(Source).one()
    assert (row.error_count, row.enabled) == (1, True)


# --- The same, on a PostgreSQL that stops answering ---------------------------------


@pytest.fixture(scope="module")
def postgres():
    server = throwaway_postgres.start_or_skip()
    try:
        yield server
    finally:
        server.stop()


def _psql(server, statement):
    """Ask the server, as its superuser, from inside its container."""
    done = subprocess.run(
        ["docker", "exec", server.container, "psql", "-h", "127.0.0.1"]
        + ["-U", "postgres", "-d", "postgres", "-At", "-c", statement],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


class Nothing(BaseCollector):
    """A feed with nothing in it: its collection asks only the database."""

    async def collect_data(self):
        return
        yield

    def parse_item(self, raw_item):
        return None


def test_the_scheduler_outlives_a_postgresql_that_refuses_it_and_goes_on_after(
    postgres, monkeypatch, caplog
):
    """A real server, a real collector, the real loop. The server refuses
    every new connection and drops the open ones, which is what a client
    sees while PostgreSQL restarts; then it takes them again."""
    engine = create_engine(postgres.url, pool_pre_ping=True, hide_parameters=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(scheduler_main, "get_db_session", factory)
    monkeypatch.setattr(collectors, "get_db_session", factory)
    monkeypatch.setitem(CollectorRegistry._collectors, "nothing", Nothing)
    source = a_source("feed", source_type="nothing")
    source.collection_interval = 0
    with factory() as session:
        session.add(source)
        session.commit()
    scheduler = CollectionScheduler()
    asyncio.run(scheduler._load_sources())
    (task,) = scheduler.tasks.values()
    task.next_run = datetime.now(timezone.utc)
    pace = Pace(monkeypatch, scheduler, reload=True)

    def runs():
        with factory() as session:
            return session.query(Source).one().collection_count

    def errors(beginning):
        return [line for line in _errors(caplog) if line.startswith(beginning)]

    async def off_the_loop(statement):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _psql, postgres, statement)

    async def scenario():
        await pace.until(lambda: runs() >= 2)
        # The server takes no connection to this database, and ends the
        # ones it has.
        await off_the_loop("ALTER DATABASE test ALLOW_CONNECTIONS false")
        await off_the_loop(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = 'test'"
        )
        # A reload and a collection have each been refused, and said so.
        await pace.until(lambda: errors("Error reloading sources: "))
        await pace.until(lambda: errors("Collection error for source feed: "))
        await pace.until(lambda: errors("The failed collection of source feed"))
        # And it takes them again: the collections go on.
        await off_the_loop("ALTER DATABASE test ALLOW_CONNECTIONS true")
        before = runs()
        await pace.until(lambda: runs() >= before + 2)

    try:
        with caplog.at_level(logging.ERROR, logger=scheduler_main.__name__):
            loop = pace.run(scenario)
    finally:
        _psql(postgres, "ALTER DATABASE test ALLOW_CONNECTIONS true")
        engine.dispose()

    # main: the first reload that was refused ended the loop.
    assert loop.exception() is None
    for line in _errors(caplog):
        first = line.splitlines()[0]
        # The class, the driver's class, and nothing the server wrote.
        assert first.endswith("OperationalError (OperationalError)"), first
        assert "accepting connections" not in line and "FATAL" not in line
    assert errors("Error reloading sources: OperationalError (OperationalError)")
    assert errors("Collection error for source feed: OperationalError")
