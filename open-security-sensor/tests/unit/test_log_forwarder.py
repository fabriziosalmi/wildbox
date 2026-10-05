"""How the log forwarder follows the files of a configured source (#638).

Each test writes real files in a temporary directory and drives the forwarder
one look at a time (``_poll_source``), so nothing here sleeps or depends on
timing; the last tests run the real loop.

What a source's file may do while the sensor runs, and what is pinned:

* be rotated by rename or by truncation, appear late, disappear;
* end in a line that is not finished, hold a line of any length, hold bytes
  that are not UTF-8;
* be a link out of the directory the source names, or not a file at all;
* grow faster than the data service takes events.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import log_forwarder  # noqa: E402
from sensor.collectors.log_forwarder import (  # noqa: E402
    CHECK_BYTES,
    HEAD_BYTES,
    MAX_FILES_PER_SOURCE,
    MAX_LINE_BYTES,
    READ_CHUNK,
    LogForwarder,
    _FileSource,
)
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    LoggingConfig,
    LogSourceConfig,
    SensorConfig,
)
from sensor.pipeline.data_forwarder import build_batch  # noqa: E402
from sensor.pipeline.data_processor import DataProcessor  # noqa: E402
from sensor.pipeline.delivery import take_delivery  # noqa: E402

NGINX_LINE = (
    '203.0.113.9 - - [05/Oct/2026:10:00:00 +0000] "GET /?id=1%27%20OR%201=1 '
    'HTTP/1.1" 200 512 "-" "sqlmap/1.7"'
)


def _source(path, **fields):
    settings = {"name": "app", "path": str(path), "format": "raw"}
    settings.update(fields)
    return LogSourceConfig(**settings)


def _forwarder(*sources, queue_size=0, sensor_log=None):
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        collection=CollectionConfig(log_forwarding=True),
        logging=LoggingConfig(file=sensor_log),
        log_sources=list(sources),
    )
    return LogForwarder(config, asyncio.Queue(maxsize=queue_size))


def _follow(path, queue_size=0, **fields):
    """A forwarder for one file source, and that source's state."""
    source = _source(path, **fields)
    forwarder = _forwarder(source, queue_size=queue_size)
    return forwarder, _FileSource(source)


async def _look(forwarder, state):
    """Look at the source until it has nothing new; the events it queued."""
    while await forwarder._poll_source(state):
        pass
    return _taken(forwarder)


def _taken(forwarder):
    """The queued events, as the pipeline sees them: without the handle by
    which the forwarder learns what became of each (test_log_positions.py)."""
    events = []
    while not forwarder.event_queue.empty():
        event = forwarder.event_queue.get_nowait()
        take_delivery(event)
        events.append(event)
    return events


def _lines(events):
    return [event["data"]["raw_message"] for event in events]


def _append(path, text):
    with open(path, "ab") as handle:
        handle.write(text if isinstance(text, bytes) else text.encode())


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


@pytest.fixture
def glob_now(monkeypatch):
    """Expand a pattern at every look instead of every few seconds."""
    monkeypatch.setattr(log_forwarder, "GLOB_INTERVAL", 0)


# -- a configured source is read ------------------------------------------


@pytest.mark.asyncio
async def test_a_line_written_to_a_configured_source_becomes_an_event(tmp_path):
    access_log = tmp_path / "access.log"
    access_log.write_text("")
    forwarder, state = _follow(access_log, name="nginx_access", format="nginx")
    await _look(forwarder, state)

    _append(access_log, NGINX_LINE + "\n")
    (event,) = await _look(forwarder, state)

    assert event["source"] == "log_forwarder"
    assert event["type"] == "log.nginx_access"
    assert event["data"]["client_ip"] == "203.0.113.9"
    assert event["data"]["status_code"] == 200
    assert event["data"]["raw_message"] == NGINX_LINE
    assert event["metadata"] == {
        "log_source": "nginx_access",
        "log_file": str(access_log),
        "format": "nginx",
    }


@pytest.mark.asyncio
async def test_what_a_file_already_holds_is_not_sent_by_default(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("before the sensor started\n")
    forwarder, state = _follow(log)

    assert await _look(forwarder, state) == []

    _append(log, "after\n")
    assert _lines(await _look(forwarder, state)) == ["after"]


@pytest.mark.asyncio
async def test_read_from_beginning_sends_what_the_file_already_holds(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("one\ntwo\n")
    forwarder, state = _follow(log, read_from="beginning")

    assert _lines(await _look(forwarder, state)) == ["one", "two"]


@pytest.mark.asyncio
async def test_starting_in_the_middle_of_a_line_does_not_send_half_of_it(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("complete\nthe first half of")
    forwarder, state = _follow(log)
    await _look(forwarder, state)

    _append(log, " a line\nthe next line\n")

    assert _lines(await _look(forwarder, state)) == ["the next line"]


# -- partial, long and undecodable lines ----------------------------------


@pytest.mark.asyncio
async def test_a_line_is_sent_when_its_newline_is_written_and_not_in_halves(
    tmp_path,
):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)

    _append(log, "GET /login?user=adm")
    assert await _look(forwarder, state) == []
    _append(log, "in HTTP/1.1")
    assert await _look(forwarder, state) == []
    _append(log, "\nnext\n")

    assert _lines(await _look(forwarder, state)) == [
        "GET /login?user=admin HTTP/1.1",
        "next",
    ]


@pytest.mark.asyncio
async def test_windows_line_endings_and_blank_lines(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)

    _append(log, "one\r\n\r\n\ntwo\r\n")

    assert _lines(await _look(forwarder, state)) == ["one", "two"]


@pytest.mark.asyncio
async def test_a_very_long_line_is_sent_once_truncated_and_the_next_is_whole(
    tmp_path,
):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)

    long_line = "A" * (5 * READ_CHUNK + 123)
    _append(log, long_line + "\nshort\n")
    long_event, short_event = await _look(forwarder, state)

    assert long_event["data"]["raw_message"] == "A" * MAX_LINE_BYTES
    assert long_event["metadata"]["truncated"] is True
    assert short_event["data"]["raw_message"] == "short"
    assert "truncated" not in short_event["metadata"]
    assert forwarder.stats == {"lines_forwarded": 2, "lines_truncated": 1}


@pytest.mark.asyncio
async def test_a_line_with_no_end_is_not_held_in_memory(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)

    held = []
    for _ in range(40):
        _append(log, b"B" * READ_CHUNK)
        while await forwarder._poll_source(state):
            held.append(len(state.tails[str(log)].partial))
    events = _taken(forwarder)
    _append(log, "\nafter\n")
    events += await _look(forwarder, state)

    assert max(held) <= MAX_LINE_BYTES
    assert _lines(events) == ["B" * MAX_LINE_BYTES, "after"]


@pytest.mark.asyncio
async def test_a_long_line_inside_one_read_is_truncated_too(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)

    _append(log, "C" * (MAX_LINE_BYTES + 1) + "\n" + "D" * MAX_LINE_BYTES + "\n")
    cut, whole = await _look(forwarder, state)

    assert cut["data"]["raw_message"] == "C" * MAX_LINE_BYTES
    assert cut["metadata"].get("truncated") is True
    assert whole["data"]["raw_message"] == "D" * MAX_LINE_BYTES
    assert "truncated" not in whole["metadata"]


@pytest.mark.asyncio
async def test_bytes_that_are_not_utf8_do_not_stop_the_line_or_the_batch(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)

    _append(log, b"caf\xe9 \xff\xfe latin-1\n" + b"\x00\x00nul bytes\n" + b"ok\n")
    events = await _look(forwarder, state)

    unknown = chr(0xFFFD)  # U+FFFD, the replacement character
    assert _lines(events) == [
        f"caf{unknown} {unknown}{unknown} latin-1",
        f"{unknown}{unknown}nul bytes",
        "ok",
    ]
    # What the data service is sent: valid JSON, with no NUL to refuse.
    body = json.dumps(build_batch(events, "sensor-a"))
    assert "u0000" not in body
    assert json.loads(body)["events"][0]["event_data"]["data"]["raw_message"]


@pytest.mark.asyncio
async def test_a_start_that_fails_leaves_no_file_open(tmp_path, monkeypatch):
    first = tmp_path / "first.log"
    first.write_text("")
    second = tmp_path / "second.log"
    second.write_text("")
    forwarder = _forwarder(_source(first, name="first"), _source(second, name="second"))
    started = []

    def fail_on_the_second(state):
        if started:
            raise RuntimeError("cannot start the second source")
        started.append(state)

        async def idle():
            await asyncio.sleep(3600)

        return idle()

    monkeypatch.setattr(forwarder, "_monitor_file", fail_on_the_second)

    with pytest.raises(RuntimeError):
        await asyncio.wait_for(forwarder.start(), timeout=5)

    assert forwarder.running is False
    assert forwarder._tasks == []
    assert [state.tails for state in forwarder._file_sources.values()] == [{}, {}]


# -- rotation and truncation ----------------------------------------------


@pytest.mark.asyncio
async def test_rotation_by_rename_loses_nothing_and_repeats_nothing(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)
    _append(log, "one\n")
    assert _lines(await _look(forwarder, state)) == ["one"]

    # logrotate: the last lines land in the old file, which is then renamed,
    # and the application reopens the path as a new, smaller file.
    _append(log, "two\nthree\n")
    os.rename(log, tmp_path / "app.log.1")
    _append(log, "four\n")

    assert _lines(await _look(forwarder, state)) == ["two", "three", "four"]
    assert list(state.tails) == [str(log)]

    _append(log, "five\n")
    assert _lines(await _look(forwarder, state)) == ["five"]


@pytest.mark.asyncio
async def test_a_new_file_larger_than_the_old_one_is_still_read_from_its_start(
    tmp_path,
):
    # The size alone does not show this rotation: the new file is longer
    # than the position reached in the old one.
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)
    _append(log, "old\n")
    await _look(forwarder, state)

    os.rename(log, tmp_path / "app.log.1")
    _append(log, "new one\nnew two\nnew three\n")

    assert _lines(await _look(forwarder, state)) == ["new one", "new two", "new three"]


@pytest.mark.asyncio
async def test_the_last_line_of_a_rotated_file_is_sent_without_its_newline(
    tmp_path,
):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)

    _append(log, "the writer was stopped mid-li")
    assert await _look(forwarder, state) == []
    os.rename(log, tmp_path / "app.log.1")

    assert _lines(await _look(forwarder, state)) == ["the writer was stopped mid-li"]


@pytest.mark.asyncio
async def test_truncation_in_place_is_read_again_from_the_beginning(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)
    _append(log, "a long line before the truncation\nand a half")
    assert _lines(await _look(forwarder, state)) == [
        "a long line before the truncation"
    ]

    # logrotate copytruncate: same file, emptied, then written again.
    os.truncate(log, 0)
    _append(log, "after\n")

    assert _lines(await _look(forwarder, state)) == ["after"]

    # And it is followed from there like any other file.
    _append(log, "and later\n")
    assert _lines(await _look(forwarder, state)) == ["and later"]


@pytest.mark.asyncio
async def test_a_file_truncated_and_written_past_the_old_position_is_noticed(
    tmp_path,
):
    # Between two looks the file is emptied and more is written than it
    # held: it is not shorter, so only its content shows it is another log.
    # Reading on from the old position would skip the new file's first
    # lines and forward the rest of one as a line.
    log = tmp_path / "access.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)
    _append(log, "old one\nold two\n")
    assert _lines(await _look(forwarder, state)) == ["old one", "old two"]

    rewritten = [f"new line number {index}" for index in range(20)]
    with open(log, "w") as handle:  # truncates in place, as a generator does
        handle.write("\n".join(rewritten) + "\n")

    assert _lines(await _look(forwarder, state)) == rewritten

    _append(log, "appended\n")
    assert _lines(await _look(forwarder, state)) == ["appended"]


BANNER = "# written by app 1.0 " + "=" * (HEAD_BYTES + 40) + "\n"


@pytest.mark.parametrize("read_from", ["beginning", "end"])
@pytest.mark.asyncio
async def test_a_file_rewritten_with_the_same_beginning_is_noticed(tmp_path, read_from):
    # The file starts with the same banner after it is rewritten, so its
    # first bytes say nothing; it is longer than before, so its size says
    # nothing either. What was read just before the position is no longer
    # there (#725). main went on from the old position: it lost the new
    # file's first lines.
    log = tmp_path / "report.log"
    log.write_text(BANNER + "old one\nold two\n")
    forwarder, state = _follow(log, read_from=read_from)
    before = _lines(await _look(forwarder, state))
    assert before == (
        [BANNER.strip(), "old one", "old two"] if read_from == "beginning" else []
    )

    rewritten = [f"new line {index}" for index in range(6)]
    with open(log, "w") as handle:
        handle.write(BANNER + "\n".join(rewritten) + "\n")

    assert _lines(await _look(forwarder, state)) == [BANNER.strip()] + rewritten

    _append(log, "appended\n")
    assert _lines(await _look(forwarder, state)) == ["appended"]


@pytest.mark.asyncio
async def test_a_file_rewritten_to_its_old_length_is_noticed_when_it_grows(tmp_path):
    log = tmp_path / "report.log"
    log.write_text(BANNER + "old one\nold two\n")
    forwarder, state = _follow(log, read_from="beginning")
    await _look(forwarder, state)

    with open(log, "w") as handle:
        handle.write(BANNER + "new one\nnew two\n")
    # As long as before: nothing says it changed, and nothing is read.
    assert await _look(forwarder, state) == []
    _append(log, "new three\n")

    assert _lines(await _look(forwarder, state)) == [
        BANNER.strip(),
        "new one",
        "new two",
        "new three",
    ]


@pytest.mark.asyncio
async def test_the_bytes_compared_span_several_short_reads(tmp_path):
    # The last read brought four bytes. What is compared is still the
    # CHECK_BYTES before the position, most of them read earlier.
    log = tmp_path / "report.log"
    log.write_text(BANNER + "an earlier line that will change\n")
    forwarder, state = _follow(log, read_from="beginning")
    await _look(forwarder, state)
    _append(log, "two\n")
    assert _lines(await _look(forwarder, state)) == ["two"]

    with open(log, "w") as handle:
        handle.write(BANNER + "AN EARLIER LINE THAT HAS CHANGED\ntwo\nthree\n")

    assert _lines(await _look(forwarder, state)) == [
        BANNER.strip(),
        "AN EARLIER LINE THAT HAS CHANGED",
        "two",
        "three",
    ]


@pytest.mark.asyncio
async def test_a_rewrite_with_another_beginning_is_noticed_whatever_follows(
    tmp_path,
):
    # The other half of the check: the same bytes before the position, but
    # the file does not begin as it did.
    log = tmp_path / "report.log"
    body = "the same line in both files " + "y" * CHECK_BYTES + "\n"
    log.write_text("header of the first file\n" + body)
    forwarder, state = _follow(log, read_from="beginning")
    await _look(forwarder, state)

    with open(log, "w") as handle:
        handle.write("HEADER OF THE OTHER FILE\n" + body + "after\n")

    assert _lines(await _look(forwarder, state)) == [
        "HEADER OF THE OTHER FILE",
        body.strip(),
        "after",
    ]


@pytest.mark.asyncio
async def test_a_rewrite_that_keeps_the_bytes_before_the_position_is_not_noticed(
    tmp_path,
):
    # The limit of the check, pinned so that the documentation stays true:
    # same first HEAD_BYTES bytes, same CHECK_BYTES bytes before the old
    # position, at least as long. It reads on from the old position.
    log = tmp_path / "report.log"
    same_end = "x" * CHECK_BYTES + "\n"
    log.write_text(BANNER + "old middle\n" + same_end)
    forwarder, state = _follow(log, read_from="beginning")
    await _look(forwarder, state)

    with open(log, "w") as handle:
        handle.write(BANNER + "NEW MIDDLE\n" + same_end + "after\n")

    assert _lines(await _look(forwarder, state)) == ["after"]


@pytest.mark.asyncio
async def test_a_file_that_only_grows_is_never_taken_for_rewritten(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("x" * 100 + "\n")
    forwarder, state = _follow(log)
    await _look(forwarder, state)

    sent = []
    for index in range(40):
        _append(log, f"line {index} " + "y" * 20 + "\n")
        sent += _lines(await _look(forwarder, state))

    assert sent == [f"line {index} " + "y" * 20 for index in range(40)]


@pytest.mark.asyncio
async def test_a_pattern_that_matches_the_rotated_name_does_not_resend_the_file(
    tmp_path, glob_now
):
    log = tmp_path / "access.log"
    log.write_text("")
    forwarder, state = _follow(tmp_path / "access.log*")
    await _look(forwarder, state)
    _append(log, "one\ntwo\n")
    assert _lines(await _look(forwarder, state)) == ["one", "two"]

    _append(log, "three\n")
    os.rename(log, tmp_path / "access.log.1")
    _append(log, "four\n")

    assert sorted(_lines(await _look(forwarder, state))) == ["four", "three"]
    assert sorted(state.tails) == [str(log), str(log) + ".1"]


# -- files that come and go -----------------------------------------------


@pytest.mark.asyncio
async def test_a_file_that_appears_later_is_read_from_its_beginning(tmp_path, caplog):
    log = tmp_path / "app.log"
    forwarder, state = _follow(log)

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        assert await _look(forwarder, state) == []
        assert await _look(forwarder, state) == []
    # Said once, with the source and the path, not at every look.
    assert _warnings(caplog) == [
        f"Log source 'app': {log} is not read: it does not exist yet"
    ]

    _append(log, "first\nsecond\n")

    assert _lines(await _look(forwarder, state)) == ["first", "second"]
    assert state.problems == {}


@pytest.mark.asyncio
async def test_a_file_that_is_removed_and_written_again(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)
    _append(log, "one\n")
    await _look(forwarder, state)

    os.unlink(log)
    assert await _look(forwarder, state) == []
    assert state.tails == {}
    _append(log, "two\n")

    assert _lines(await _look(forwarder, state)) == ["two"]


@pytest.mark.asyncio
async def test_a_pattern_picks_up_new_files_and_only_matching_ones(tmp_path, glob_now):
    (tmp_path / "a.log").write_text("old a\n")
    (tmp_path / "notes.txt").write_text("")
    (tmp_path / "a.log.2.gz").write_bytes(b"\x1f\x8b\x08\x00binary\n")
    forwarder, state = _follow(tmp_path / "*.log*")
    await _look(forwarder, state)

    _append(tmp_path / "a.log", "a\n")
    _append(tmp_path / "b.log", "b, a file that did not exist\n")
    _append(tmp_path / "notes.txt", "not a log\n")
    _append(tmp_path / "a.log.2.gz", b"more binary\n")
    events = await _look(forwarder, state)

    assert sorted(_lines(events)) == ["a", "b, a file that did not exist"]
    assert {event["metadata"]["log_file"] for event in events} == {
        str(tmp_path / "a.log"),
        str(tmp_path / "b.log"),
    }


@pytest.mark.asyncio
async def test_a_pattern_with_no_match_is_reported_once(tmp_path, glob_now, caplog):
    forwarder, state = _follow(tmp_path / "*.log")

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await _look(forwarder, state)
        await _look(forwarder, state)

    assert _warnings(caplog) == [
        f"Log source 'app': {tmp_path}/*.log is not read: no file matches the "
        f"pattern yet"
    ]


@pytest.mark.asyncio
async def test_a_pattern_in_a_directory_that_appears_later(tmp_path, glob_now, caplog):
    logs = tmp_path / "app" / "logs"
    forwarder, state = _follow(logs / "*.log")

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await _look(forwarder, state)
    assert _warnings(caplog) == [
        f"Log source 'app': {logs}/*.log is not read: the directory {logs} does "
        f"not exist yet"
    ]

    logs.mkdir(parents=True)
    _append(logs / "one.log", "first\n")

    assert _lines(await _look(forwarder, state)) == ["first"]
    assert state.problems == {}


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="root lists a directory whatever its mode",
)
@pytest.mark.asyncio
async def test_a_directory_that_cannot_be_listed_is_reported_as_such(
    tmp_path, glob_now, caplog
):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "app.log").write_text("")
    logs.chmod(0o000)
    forwarder, state = _follow(logs / "*.log")

    try:
        with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
            await _look(forwarder, state)
    finally:
        logs.chmod(0o755)

    assert state.problems == {
        f"{logs}/*.log": f"this process (uid {os.geteuid()}) is not allowed to "
        f"list {logs}"
    }


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="root reaches a file whatever its directory's mode",
)
@pytest.mark.asyncio
async def test_a_path_that_cannot_be_looked_at_is_not_taken_for_a_rotation(
    tmp_path,
):
    # The directory loses its search permission for a moment. Taking that
    # for a rotation would close the file, and open it again as a new one:
    # everything it holds would be forwarded a second time.
    logs = tmp_path / "logs"
    logs.mkdir()
    log = logs / "app.log"
    log.write_text("")
    forwarder, state = _follow(log)
    await _look(forwarder, state)
    _append(log, "one\n")
    assert _lines(await _look(forwarder, state)) == ["one"]

    with open(log, "ab") as writer:
        logs.chmod(0o000)
        try:
            writer.write(b"two\n")
            writer.flush()
            during = _lines(await _look(forwarder, state))
        finally:
            logs.chmod(0o755)
    _append(log, "three\n")
    after = _lines(await _look(forwarder, state))

    assert during == ["two"]
    assert after == ["three"]


@pytest.mark.asyncio
async def test_a_pattern_reads_a_bounded_number_of_files(tmp_path, glob_now, caplog):
    for index in range(MAX_FILES_PER_SOURCE + 3):
        (tmp_path / f"{index:03}.log").write_text("")
    forwarder, state = _follow(tmp_path / "*.log")

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await _look(forwarder, state)

    assert len(state.tails) == MAX_FILES_PER_SOURCE
    (warning,) = _warnings(caplog)
    assert f"matches {MAX_FILES_PER_SOURCE + 3} files" in warning


# -- what a source must not read ------------------------------------------


@pytest.mark.asyncio
async def test_a_link_out_of_the_sources_directory_is_not_followed(
    tmp_path, glob_now, caplog
):
    logs = tmp_path / "logs"
    logs.mkdir()
    secret = tmp_path / "shadow"
    secret.write_text("root:$6$hash:19000:0:99999:7:::\n")
    (logs / "app.log").write_text("")
    os.symlink(secret, logs / "evil.log")
    forwarder, state = _follow(logs / "*.log", read_from="beginning")

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await _look(forwarder, state)
        _append(secret, "more:secret\n")
        _append(logs / "app.log", "a log line\n")
        events = await _look(forwarder, state)

    assert _lines(events) == ["a log line"]
    assert list(state.tails) == [str(logs / "app.log")]
    (warning,) = _warnings(caplog)
    assert "Log source 'app'" in warning and str(logs / "evil.log") in warning
    assert "outside" in warning


@pytest.mark.asyncio
async def test_a_named_path_that_is_a_link_out_is_not_followed_either(tmp_path, caplog):
    logs = tmp_path / "logs"
    logs.mkdir()
    secret = tmp_path / "shadow"
    secret.write_text("root:$6$hash\n")
    os.symlink(secret, logs / "app.log")
    forwarder, state = _follow(logs / "app.log", read_from="beginning")

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        assert await _look(forwarder, state) == []

    assert state.tails == {}
    assert "outside" in state.problems[str(logs / "app.log")]


@pytest.mark.asyncio
async def test_a_directory_link_out_of_the_sources_directory_is_not_followed(
    tmp_path, glob_now
):
    sites = tmp_path / "sites"
    (sites / "one").mkdir(parents=True)
    (sites / "one" / "access.log").write_text("one\n")
    elsewhere = tmp_path / "etc"
    elsewhere.mkdir()
    (elsewhere / "access.log").write_text("not a site's log\n")
    os.symlink(elsewhere, sites / "two")
    forwarder, state = _follow(sites / "*" / "access.log", read_from="beginning")

    assert _lines(await _look(forwarder, state)) == ["one"]
    assert "outside" in state.problems[str(sites / "two" / "access.log")]


@pytest.mark.asyncio
async def test_a_link_inside_the_directory_is_read_and_only_once(tmp_path, glob_now):
    (tmp_path / "app-1.log").write_text("")
    os.symlink(tmp_path / "app-1.log", tmp_path / "current.log")
    forwarder, state = _follow(tmp_path / "*.log")
    await _look(forwarder, state)

    _append(tmp_path / "app-1.log", "once\n")

    assert _lines(await _look(forwarder, state)) == ["once"]
    assert len(state.tails) == 1


@pytest.mark.asyncio
async def test_a_link_swapped_in_after_the_check_is_not_followed(tmp_path, monkeypatch):
    # The path is resolved, found inside the directory, and then opened
    # without following links: a link put there in between is refused.
    logs = tmp_path / "logs"
    logs.mkdir()
    secret = tmp_path / "shadow"
    secret.write_text("root:$6$hash\n")
    os.symlink(secret, logs / "app.log")
    forwarder, state = _follow(logs / "app.log", read_from="beginning")
    real_realpath = os.path.realpath

    def realpath_before_the_swap(path, *args, **kwargs):
        # What the check saw: a plain file, where there is now a link.
        resolved = real_realpath(path, *args, **kwargs)
        return str(logs / "app.log") if resolved == str(secret) else resolved

    monkeypatch.setattr(log_forwarder.os.path, "realpath", realpath_before_the_swap)
    events = await _look(forwarder, state)
    monkeypatch.undo()

    assert events == []
    assert state.tails == {}
    assert "changed into a link" in state.problems[str(logs / "app.log")]


@pytest.mark.asyncio
async def test_something_that_is_not_a_regular_file_is_not_read(
    tmp_path, glob_now, caplog
):
    (tmp_path / "dir.log").mkdir()
    os.mkfifo(tmp_path / "pipe.log")
    (tmp_path / "real.log").write_text("")
    forwarder, state = _follow(tmp_path / "*.log")

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await asyncio.wait_for(_look(forwarder, state), timeout=5)

    assert list(state.tails) == [str(tmp_path / "real.log")]
    assert state.problems == {
        str(tmp_path / "dir.log"): "it is not a regular file",
        str(tmp_path / "pipe.log"): "it is not a regular file",
    }


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="root reads a file whatever its mode",
)
@pytest.mark.asyncio
async def test_an_unreadable_file_is_reported_and_read_once_it_is_readable(
    tmp_path, caplog
):
    log = tmp_path / "auth.log"
    log.write_text("written before the sensor could read it\n")
    log.chmod(0o000)
    forwarder, state = _follow(log, name="auth")

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        assert await _look(forwarder, state) == []
        assert await _look(forwarder, state) == []
    (warning,) = _warnings(caplog)
    assert warning == (
        f"Log source 'auth': {log} is not read: this process "
        f"(uid {os.geteuid()}) is not allowed to read it"
    )

    log.chmod(0o644)
    _append(log, "after\n")

    assert _lines(await _look(forwarder, state)) == ["after"]


@pytest.mark.asyncio
async def test_the_sensors_own_log_is_never_a_source(tmp_path, glob_now):
    own = tmp_path / "sensor.log"
    own.write_text("")
    (tmp_path / "sensor.log.1").write_text("")
    (tmp_path / "app.log").write_text("")
    source = _source(tmp_path / "*.log*")
    forwarder = _forwarder(source, sensor_log=str(own))
    state = _FileSource(source)
    await _look(forwarder, state)

    _append(own, "a line the sensor logged about forwarding a line\n")
    _append(tmp_path / "sensor.log.1", "rotated\n")
    _append(tmp_path / "app.log", "app\n")

    assert _lines(await _look(forwarder, state)) == ["app"]
    assert state.problems[str(own)] == "it is the sensor's own log file"


# -- back-pressure --------------------------------------------------------


@pytest.mark.asyncio
async def test_a_full_queue_stops_the_reading_and_nothing_is_lost(tmp_path):
    log = tmp_path / "app.log"
    expected = [f"line {index:06}" for index in range(60_000)]
    log.write_text("\n".join(expected) + "\n")
    assert log.stat().st_size > 10 * READ_CHUNK
    forwarder, state = _follow(log, queue_size=10, read_from="beginning")

    async def read_everything():
        while await forwarder._poll_source(state):
            pass

    # Nobody takes events: the data service is unreachable, the pipeline
    # behind the queue has stopped.
    reading = asyncio.ensure_future(read_everything())
    for _ in range(200):
        await asyncio.sleep(0)

    assert not reading.done()
    assert forwarder.event_queue.full()
    # It holds one chunk, not the file.
    assert state.tails[str(log)].position == READ_CHUNK

    # The pipeline moves again: everything arrives, once and in order.
    received = []

    async def take():
        while True:
            event = await forwarder.event_queue.get()
            received.append(event["data"]["raw_message"])

    taking = asyncio.ensure_future(take())
    await asyncio.wait_for(reading, timeout=30)
    while not forwarder.event_queue.empty():
        await asyncio.sleep(0)
    taking.cancel()

    assert received == expected


@pytest.mark.asyncio
async def test_one_busy_file_does_not_starve_the_sources_other_files(
    tmp_path, glob_now, monkeypatch
):
    monkeypatch.setattr(log_forwarder, "MAX_READ_PER_PASS", 2 * READ_CHUNK)
    (tmp_path / "a-busy.log").write_text("x" * 100 + "\n")
    (tmp_path / "b-quiet.log").write_text("")
    forwarder, state = _follow(tmp_path / "*.log")
    await _look(forwarder, state)
    _append(tmp_path / "a-busy.log", ("busy\n" * READ_CHUNK))
    _append(tmp_path / "b-quiet.log", "quiet\n")

    assert await forwarder._poll_source(state) is True

    # One look read part of the busy file and all of the quiet one.
    assert "quiet" in _lines(_taken(forwarder))
    busy = state.tails[str(tmp_path / "a-busy.log")]
    assert busy.position < (tmp_path / "a-busy.log").stat().st_size


# -- the running forwarder ------------------------------------------------


async def _next_event(forwarder, timeout=5):
    event = await asyncio.wait_for(forwarder.event_queue.get(), timeout=timeout)
    take_delivery(event)
    return event


@pytest.mark.asyncio
async def test_the_running_forwarder_follows_its_sources_and_stops_cleanly(
    tmp_path,
):
    log = tmp_path / "access.log"
    log.write_text("")
    forwarder = _forwarder(_source(log, name="nginx_access", format="nginx"))
    forwarder.poll_interval = 0.01

    await forwarder.start()
    try:
        _append(log, NGINX_LINE + "\n")
        event = await _next_event(forwarder)
        os.rename(log, tmp_path / "access.log.1")
        _append(log, NGINX_LINE.replace("203.0.113.9", "198.51.100.7") + "\n")
        rotated = await _next_event(forwarder)

        size = log.stat().st_size
        status = forwarder.get_status()
    finally:
        await forwarder.stop()

    assert event["type"] == "log.nginx_access"
    assert event["data"]["client_ip"] == "203.0.113.9"
    assert rotated["data"]["client_ip"] == "198.51.100.7"
    assert status["default_sources"] is False
    assert status["monitored_files"] == 1
    assert status["log_sources"] == [
        {
            "name": "nginx_access",
            "type": "file",
            "enabled": True,
            "path": str(log),
            "format": "nginx",
            "files": [str(log)],
            "problems": {},
            # Read to its end; nothing accepted, as nothing took the events
            # further than the queue.
            "positions": {str(log): {"read": size, "accepted": 0, "behind": 0}},
        }
    ]
    assert status["positions"] == {
        "persisted": False,
        "file": None,
        "last_saved": None,
        "problem": "data_dir is not set: positions are kept in memory only",
    }
    # Stopped: no task left, no file left open.
    assert forwarder._tasks == []
    assert forwarder._file_sources["nginx_access"].tails == {}


@pytest.mark.asyncio
async def test_stop_ends_a_forwarder_that_is_waiting_on_a_full_queue(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("one\ntwo\nthree\n")
    forwarder = _forwarder(_source(log, read_from="beginning"), queue_size=1)
    forwarder.poll_interval = 0.01

    await forwarder.start()
    for _ in range(50):
        await asyncio.sleep(0)
    assert forwarder.event_queue.full()
    (task,) = forwarder._tasks

    await asyncio.wait_for(forwarder.stop(), timeout=5)

    assert task.done()
    assert forwarder._file_sources["app"].tails == {}


@pytest.mark.asyncio
async def test_what_is_wrong_with_a_source_is_logged_when_the_forwarder_starts(
    tmp_path, caplog
):
    present = tmp_path / "present.log"
    present.write_text("")
    absent = tmp_path / "absent.log"
    forwarder = _forwarder(
        _source(present, name="present"), _source(absent, name="absent")
    )

    with caplog.at_level(logging.INFO, logger=log_forwarder.__name__):
        await forwarder.start()
        await forwarder.stop()

    messages = [record.getMessage() for record in caplog.records]
    started = messages.index("Log forwarder started with 2 sources")
    warning = f"Log source 'absent': {absent} is not read: it does not exist yet"
    assert messages.index(warning) < started
    assert forwarder.get_status()["log_sources"][1]["problems"] == {
        str(absent): "it does not exist yet"
    }


@pytest.mark.asyncio
async def test_a_source_this_platform_cannot_read_is_skipped_with_a_warning(
    tmp_path, monkeypatch, caplog
):
    for name in ("linux", "windows", "macos"):
        monkeypatch.setattr(log_forwarder, f"is_{name}", lambda: False)
    log = tmp_path / "app.log"
    log.write_text("")
    forwarder = _forwarder(
        LogSourceConfig(name="journal", type="journald", format="json"),
        LogSourceConfig(
            name="security",
            type="windows_event",
            log_name="Security",
            format="windows_event",
        ),
        LogSourceConfig(name="unified", type="unified_log", format="json"),
        _source(log),
    )

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await forwarder.start()
        tasks = len(forwarder._tasks)
        await forwarder.stop()

    assert tasks == 1
    assert _warnings(caplog)[:3] == [
        "Log source 'journal' (journald) is skipped: the systemd journal is "
        "read on Linux only",
        "Log source 'security' (windows_event) is skipped: the Windows Event "
        "Log is read on Windows only",
        "Log source 'unified' (unified_log) is skipped: the unified log is "
        "read on macOS only",
    ]
    # And, with no data_dir, that positions will not outlive the sensor.
    (memory_only,) = _warnings(caplog)[3:]
    assert memory_only.startswith("data_dir is not set: read positions are kept")


@pytest.mark.asyncio
async def test_no_enabled_source_is_said_and_nothing_is_read(caplog):
    forwarder = _forwarder()

    with caplog.at_level(logging.WARNING, logger=log_forwarder.__name__):
        await forwarder.start()
        await forwarder.stop()

    assert forwarder._tasks == []
    assert any("no log source is" in message for message in _warnings(caplog))


@pytest.mark.asyncio
async def test_a_forwarded_line_reaches_the_ingest_batch_as_a_security_event(
    tmp_path,
):
    log = tmp_path / "access.log"
    log.write_text("")
    forwarder, state = _follow(log, name="nginx_access", format="nginx")
    await _look(forwarder, state)
    _append(log, NGINX_LINE + "\n")
    (collected,) = await _look(forwarder, state)

    processor = DataProcessor(forwarder.config, asyncio.Queue(), asyncio.Queue())
    processed = await processor._process_single_event(collected)
    (sent,) = build_batch([processed], "web-1")["events"]

    assert sent["sensor_id"] == "web-1"
    assert sent["event_type"] == "security_event"
    assert sent["tags"] == ["log.nginx_access"]
    assert sent["event_data"]["data"]["request"].startswith("GET /?id=1%27")
    assert sent["event_data"]["metadata"]["log_file"] == str(log)
