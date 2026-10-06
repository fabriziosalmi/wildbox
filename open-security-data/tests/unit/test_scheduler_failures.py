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
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.collectors import (  # noqa: E402
    CollectionResult,
    CollectionStatus,
    CollectorRegistry,
)
from app.models import Source  # noqa: E402
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
