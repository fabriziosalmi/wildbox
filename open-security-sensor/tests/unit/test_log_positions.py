"""The log forwarder goes on, after a restart, where the data service stopped (#725).

Positions used to live in memory only: after a restart a ``read_from: end``
source skipped what was written while the sensor was down, and a
``read_from: beginning`` source sent every file again.

Each test here is a sequence of runs of the forwarder on one data directory.
A run reads its sources one look at a time, as in test_log_forwarder.py, and
the test plays the rest of the pipeline: it takes the events off the queue
and settles the ones "the data service accepted". Nothing sleeps. The last
tests run the real pipeline and the real agent.
"""

import asyncio
import hashlib
import json
import logging
import os
import stat
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import log_forwarder, position_store  # noqa: E402
from sensor.collectors.log_forwarder import (  # noqa: E402
    MAX_LINE_BYTES,
    READ_CHUNK,
    LogForwarder,
)
from sensor.collectors.position_store import MAX_FILES, STATE_FILE  # noqa: E402
from sensor.core.agent import SecuritySensorAgent  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    FIMConfig,
    LogSourceConfig,
    NetworkConfig,
    SensorConfig,
)
from sensor.pipeline import data_forwarder  # noqa: E402
from sensor.pipeline.data_forwarder import RETRY, SENT, DataForwarder  # noqa: E402
from sensor.pipeline.data_processor import DataProcessor  # noqa: E402
from sensor.pipeline.delivery import take_delivery  # noqa: E402

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def _source(path, **fields):
    settings = {"name": "app", "path": str(path), "format": "raw"}
    settings.update(fields)
    return LogSourceConfig(**settings)


def _config(data_dir, *sources, api_key="", **data_lake):
    return SensorConfig(
        data_lake=DataLakeConfig(
            endpoint="https://gateway.example", api_key=api_key, **data_lake
        ),
        collection=CollectionConfig(
            process_events=False,
            network_connections=False,
            file_monitoring=False,
            user_events=False,
            system_inventory=False,
            log_forwarding=True,
        ),
        fim=FIMConfig(enabled=False),
        network=NetworkConfig(enable_api=False),
        log_sources=list(sources),
        data_dir=str(data_dir) if data_dir else None,
    )


class Run:
    """One run of the log forwarder: from a start of the sensor to its stop."""

    def __init__(self, data_dir, *sources):
        self.forwarder = LogForwarder(_config(data_dir, *sources), asyncio.Queue())
        self.states = [self.forwarder._file_source(source) for source in sources]
        for state in self.states:
            self.forwarder._file_sources[state.source.name] = state
        # What became of each line read is not known yet: (line, delivery).
        self.unsettled = []

    async def read(self):
        """Look at every source until none has anything new; the lines read."""
        lines = []
        progressed = True
        while progressed:
            progressed = False
            for state in self.states:
                progressed = await self.forwarder._poll_source(state) or progressed
            while not self.forwarder.event_queue.empty():
                event = self.forwarder.event_queue.get_nowait()
                line = event["data"]["raw_message"]
                self.unsettled.append((line, take_delivery(event)))
                lines.append(line)
        return lines

    def accept(self, *lines):
        """The data service accepted these lines' events (all, by default)."""
        chosen = [item for item in self.unsettled if not lines or item[0] in lines]
        assert chosen and (not lines or len(chosen) == len(lines))
        for item in chosen:
            self.unsettled.remove(item)
            item[1].settle()

    def stop(self):
        """An orderly stop: files closed, positions written."""
        for state in self.states:
            self.forwarder._close_all(state)
        self.forwarder.save_positions()

    def kill(self):
        """SIGKILL: files closed by the kernel, nothing written."""
        for state in self.states:
            self.forwarder._close_all(state)


async def _run(data_dir, *sources):
    """A run that has read everything and seen all of it accepted."""
    run = Run(data_dir, *sources)
    lines = await run.read()
    if lines:
        run.accept()
    return run, lines


def _append(path, text):
    with open(path, "ab") as handle:
        handle.write(text if isinstance(text, bytes) else text.encode())


def _state(data_dir):
    return json.loads((Path(data_dir) / STATE_FILE).read_text())


def _saved_offset(data_dir, name="app"):
    (entry,) = _state(data_dir)["sources"][name]["files"]
    return entry["offset"]


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.fixture
def glob_now(monkeypatch):
    monkeypatch.setattr(log_forwarder, "GLOB_INTERVAL", 0)


@pytest.fixture
def data_dir(tmp_path):
    directory = tmp_path / "data"
    directory.mkdir()
    return directory


@pytest.fixture
def log(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    return logs / "app.log"


# -- a restart neither skips nor resends -----------------------------------


@pytest.mark.parametrize("read_from", ["end", "beginning"])
@pytest.mark.asyncio
async def test_a_restart_sends_what_was_written_meanwhile_and_nothing_twice(
    data_dir, log, read_from
):
    log.write_text("before the sensor's first start\n")
    source = _source(log, read_from=read_from)

    run, first = await _run(data_dir, source)
    _append(log, "while running\n")
    first += await run.read()
    run.accept()
    run.stop()
    _append(log, "while the sensor was down\n")
    run, second = await _run(data_dir, source)
    _append(log, "after the restart\n")
    second += await run.read()

    # read_from says where the first start begins, and only that.
    assert first == (
        ["before the sensor's first start"] * (read_from == "beginning")
    ) + ["while running"]
    # main: [] with read_from end (the line written meanwhile was skipped),
    # and the whole file again with beginning.
    assert second == ["while the sensor was down", "after the restart"]


@pytest.mark.asyncio
async def test_the_position_kept_is_the_last_line_accepted_not_the_last_read(
    data_dir, log
):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "one\ntwo\nthree\nfour\n")
    assert await run.read() == ["one", "two", "three", "four"]

    # The data service has taken the first batch only; the rest is still in
    # the sensor when it stops.
    run.accept("one", "two")
    run.stop()

    assert _saved_offset(data_dir) == len("one\ntwo\n")
    run, again = await _run(data_dir, source)
    assert again == ["three", "four"]


@pytest.mark.asyncio
async def test_nothing_accepted_means_everything_is_read_again(data_dir, log):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "one\ntwo\n")
    assert await run.read() == ["one", "two"]
    run.stop()  # the gateway was down the whole time

    run, again = await _run(data_dir, source)

    assert again == ["one", "two"]


@pytest.mark.asyncio
async def test_a_line_accepted_before_an_earlier_one_does_not_move_the_position(
    data_dir, log
):
    # The processor's workers may finish out of order, and a batch may be
    # refused while the next is accepted: the position passes a line only
    # when every line before it is settled too.
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "one\ntwo\nthree\n")
    await run.read()
    (tail,) = run.states[0].tails.values()

    run.accept("three")
    assert tail.record.offset == 0
    run.accept("one")
    assert tail.record.offset == len("one\n")
    run.accept("two")
    assert tail.record.offset == len("one\ntwo\nthree\n")
    assert not tail.pending


@pytest.mark.asyncio
async def test_a_killed_sensor_sends_again_only_what_was_accepted_since_the_last_save(
    data_dir, log
):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "one\ntwo\n")
    await run.read()
    run.accept()
    assert run.forwarder.save_positions() is True  # the periodic write
    _append(log, "three\n")
    await run.read()
    run.accept()
    run.kill()  # before the next write

    run, again = await _run(data_dir, source)

    # At least once, never less: "three" is sent a second time.
    assert again == ["three"]


@pytest.mark.asyncio
async def test_a_line_whose_newline_was_not_written_is_sent_whole_after_the_restart(
    data_dir, log
):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "complete\nthe first half of")
    assert await run.read() == ["complete"]
    run.accept()
    run.stop()

    _append(log, " a line\n")
    run, again = await _run(data_dir, source)

    assert again == ["the first half of a line"]


@pytest.mark.asyncio
async def test_the_offset_of_a_line_read_in_two_parts_is_where_it_ends(data_dir, log):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "one\nthe first half of")
    await run.read()
    _append(log, " a line\ntwo\n")
    assert await run.read() == ["the first half of a line", "two"]
    (tail,) = run.states[0].tails.values()

    run.accept("one", "the first half of a line")
    assert tail.record.offset == len("one\nthe first half of a line\n")
    run.accept("two")
    assert tail.record.offset == log.stat().st_size


@pytest.mark.asyncio
async def test_a_line_sent_cut_is_not_sent_again_and_its_rest_is_no_line(data_dir, log):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "A" * (3 * READ_CHUNK))  # no newline yet: sent once, cut
    assert await run.read() == ["A" * MAX_LINE_BYTES]
    run.accept()
    run.stop()

    _append(log, "the rest of the long line\nthe next line\n")
    run, again = await _run(data_dir, source)

    assert again == ["the next line"]


@pytest.mark.asyncio
async def test_blank_lines_do_not_hold_the_position_back(data_dir, log):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "one\n\n\n\ntwo\n")
    assert await run.read() == ["one", "two"]
    run.accept()
    run.stop()

    assert _saved_offset(data_dir) == len("one\n\n\n\ntwo\n")


# -- the file is not the one the position was taken from --------------------


@pytest.mark.asyncio
async def test_a_file_rotated_while_the_sensor_was_down_is_read_from_its_beginning(
    data_dir, log
):
    log.write_text("")
    source = _source(log)  # read_from: end, which must not apply here
    run, _ = await _run(data_dir, source)
    _append(log, "one\n")
    await run.read()
    run.accept()
    run.stop()

    _append(log, "two, in the old file\n")
    os.rename(log, str(log) + ".1")
    _append(log, "three, in the new file\n")
    run, again = await _run(data_dir, source)

    # The new file is a file that appeared: all of it. The old one is no
    # longer named by the source: what was added to it is not read.
    assert again == ["three, in the new file"]


@pytest.mark.asyncio
async def test_a_pattern_that_matches_the_rotated_file_reads_the_rest_of_it(
    data_dir, log, glob_now
):
    log.write_text("")
    source = _source(str(log) + "*")
    run, _ = await _run(data_dir, source)
    _append(log, "one\n")
    await run.read()
    run.accept()
    run.stop()

    _append(log, "two, in the old file\n")
    os.rename(log, str(log) + ".1")
    _append(log, "three, in the new file\n")
    run, again = await _run(data_dir, source)

    assert sorted(again) == ["three, in the new file", "two, in the old file"]


@pytest.mark.asyncio
async def test_a_file_renamed_while_it_is_read_is_saved_under_its_new_name(
    data_dir, log, glob_now
):
    log.write_text("")
    source = _source(str(log) + "*")
    run, _ = await _run(data_dir, source)
    _append(log, "one\n")
    await run.read()
    run.accept()
    old = os.stat(log).st_ino

    os.rename(log, str(log) + ".1")
    _append(log, "two\n")
    await run.read()
    run.accept()
    run.stop()

    saved = {
        entry["path"]: (entry["inode"], entry["offset"])
        for entry in _state(data_dir)["sources"]["app"]["files"]
    }
    assert saved == {
        str(log) + ".1": (old, len("one\n")),
        str(log): (os.stat(log).st_ino, len("two\n")),
    }


@pytest.mark.asyncio
async def test_a_file_truncated_while_the_sensor_was_down_is_read_from_its_beginning(
    data_dir, log
):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "a long line before the truncation\n")
    await run.read()
    run.accept()
    run.stop()

    os.truncate(log, 0)
    _append(log, "after\n")
    run, again = await _run(data_dir, source)

    assert again == ["after"]


@pytest.mark.asyncio
async def test_a_file_rewritten_while_the_sensor_was_down_is_read_from_its_beginning(
    data_dir, log
):
    # Same inode, longer than the saved offset: only the bytes say it is
    # another log.
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "old one\nold two\n")
    await run.read()
    run.accept()
    run.stop()

    with open(log, "w") as handle:
        handle.write("new one\nnew two\nnew three\n")
    run, again = await _run(data_dir, source)

    assert again == ["new one", "new two", "new three"]


@pytest.mark.parametrize("field", ["check", "head"])
@pytest.mark.asyncio
async def test_a_position_is_not_used_for_a_file_whose_bytes_do_not_match(
    data_dir, log, field
):
    # Another file can come to have the device and inode of a removed one.
    # Here the saved digests are another file's.
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "one\ntwo\n")
    await run.read()
    run.accept()
    run.stop()
    document = _state(data_dir)
    document["sources"]["app"]["files"][0][field] = "0" * 64
    (data_dir / STATE_FILE).write_text(json.dumps(document))

    run, again = await _run(data_dir, source)

    assert again == ["one", "two"]


@pytest.mark.asyncio
async def test_a_removed_file_leaves_no_position_for_the_one_that_takes_its_name(
    data_dir, log
):
    # Removed while the sensor runs, and written again with the same first
    # lines, quite possibly under the same inode: the old file's position
    # must not make the sensor skip them.
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "banner\none\n")
    await run.read()
    run.accept()
    os.unlink(log)
    assert await run.read() == []
    assert run.states[0].records == {}

    _append(log, "banner\none\ntwo\n")

    assert await run.read() == ["banner", "one", "two"]


# -- which sources are known ------------------------------------------------


@pytest.mark.asyncio
async def test_a_file_that_appeared_while_the_sensor_was_down_is_read_whole(
    data_dir, log, glob_now
):
    log.write_text("")
    source = _source(log.parent / "*.log")  # read_from: end
    run, _ = await _run(data_dir, source)
    run.stop()

    _append(log.parent / "new.log", "written to a file the sensor never saw\n")
    run, again = await _run(data_dir, source)

    assert again == ["written to a file the sensor never saw"]


@pytest.mark.asyncio
async def test_a_source_that_read_nothing_is_still_known_after_a_restart(data_dir, log):
    source = _source(log)  # the file does not exist yet
    run, _ = await _run(data_dir, source)
    run.stop()
    assert _state(data_dir)["sources"] == {
        "app": {"type": "file", "path": str(log), "files": []}
    }

    _append(log, "written while the sensor was down\n")
    run, again = await _run(data_dir, source)

    assert again == ["written while the sensor was down"]


@pytest.mark.asyncio
async def test_a_source_pointed_at_another_path_starts_as_its_read_from_says(
    data_dir, log
):
    other = log.parent / "other.log"
    other.write_text("already in the other file\n")
    log.write_text("")
    run, _ = await _run(data_dir, _source(log))
    run.stop()

    # Same name, another path: not the source that was read. Reading the
    # whole of a file the operator just pointed it at would be a surprise.
    run, again = await _run(data_dir, _source(other))
    _append(other, "new\n")
    again += await run.read()

    assert again == ["new"]


@pytest.mark.asyncio
async def test_a_new_source_does_not_disturb_the_others(data_dir, log):
    second_log = log.parent / "second.log"
    second_log.write_text("already there\n")
    log.write_text("")
    first = _source(log, name="first")
    second = _source(second_log, name="second")
    run, _ = await _run(data_dir, first)
    _append(log, "one\n")
    await run.read()
    run.accept()
    run.stop()

    _append(log, "two\n")
    run, again = await _run(data_dir, first, second)
    run.stop()

    assert again == ["two"]
    assert set(_state(data_dir)["sources"]) == {"first", "second"}


@pytest.mark.asyncio
async def test_a_disabled_source_keeps_its_position_and_a_removed_one_loses_it(
    data_dir, log
):
    kept_log = log.parent / "kept.log"
    kept_log.write_text("")
    log.write_text("")
    kept = _source(kept_log, name="kept")
    gone = _source(log, name="gone")
    run, _ = await _run(data_dir, kept, gone)
    _append(kept_log, "one\n")
    await run.read()
    run.accept()
    run.stop()
    saved = _state(data_dir)["sources"]["kept"]

    # "kept" is switched off for a while, "gone" leaves the configuration.
    forwarder = LogForwarder(
        _config(data_dir, _source(kept_log, name="kept", enabled=False)),
        asyncio.Queue(),
    )
    forwarder._positions_dirty = True
    forwarder.save_positions()

    assert _state(data_dir)["sources"] == {"kept": saved}
    _append(kept_log, "two\n")
    run, again = await _run(data_dir, kept)
    assert again == ["two"]


# -- the state file ---------------------------------------------------------


@pytest.mark.asyncio
async def test_the_state_file_holds_identities_offsets_and_digests_only(data_dir, log):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "a line with a secret-looking token 4f9a\n")
    await run.read()
    run.accept()
    run.stop()

    found = os.stat(log)
    document = _state(data_dir)
    (entry,) = document["sources"]["app"]["files"]
    assert set(document) == {"format", "version", "saved_at", "sources"}
    assert (document["format"], document["version"]) == (
        "wildbox-sensor-log-positions",
        1,
    )
    assert entry["device"] == found.st_dev and entry["inode"] == found.st_ino
    assert entry["offset"] == found.st_size
    assert entry["path"] == str(log)
    # The file is recognized by its first bytes (all of them: it is short)
    # and by the 64 before the offset.
    content = log.read_bytes()
    assert entry["head_bytes"] == len(content) < 256
    assert entry["head"] == hashlib.sha256(content).hexdigest()
    assert entry["check"] == hashlib.sha256(content[-64:]).hexdigest()
    # No log content, and nobody else's to read.
    assert "token" not in (data_dir / STATE_FILE).read_text()
    assert stat.S_IMODE(os.stat(data_dir / STATE_FILE).st_mode) == 0o600
    assert os.listdir(data_dir) == [STATE_FILE]


@pytest.mark.asyncio
async def test_positions_are_written_only_when_they_have_moved(data_dir, log):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)

    assert run.forwarder.save_positions() is True  # the source is known now
    assert run.forwarder.save_positions() is False
    _append(log, "one\n")
    await run.read()
    assert run.forwarder.save_positions() is False  # read, not accepted
    run.accept()
    assert run.forwarder.save_positions() is True


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not json",
        b"\x00\xff\xfe",
        b"[]",
        b'{"format": "something-else", "version": 1, "saved_at": "", "sources": {}}',
    ],
)
@pytest.mark.asyncio
async def test_a_state_file_that_cannot_be_used_is_ignored_with_a_warning(
    data_dir, log, caplog, content
):
    log.write_text("before\n")
    (data_dir / STATE_FILE).write_bytes(content)
    source = _source(log)  # read_from: end

    with caplog.at_level(logging.WARNING, logger=position_store.__name__):
        run, lines = await _run(data_dir, source)
    _append(log, "after\n")
    lines += await run.read()
    run.accept()
    run.stop()

    # As a first start: read_from applies, and the file is replaced.
    assert lines == ["after"]
    (warning,) = _warnings(caplog)
    assert warning.startswith(
        f"The saved log positions in {data_dir / STATE_FILE} are ignored: "
    )
    assert _saved_offset(data_dir) == len("before\nafter\n")


@pytest.mark.asyncio
async def test_without_a_data_directory_nothing_is_written_and_every_start_is_a_first(
    tmp_path, log
):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(None, source)
    _append(log, "one\n")
    await run.read()
    line, delivery = run.unsettled[0]

    # Not readable again after a restart: what is unsent at stop is lost,
    # and the forwarder counts it so.
    assert delivery.replayable is False
    run.accept()
    assert run.forwarder.save_positions() is False
    run.stop()
    assert run.forwarder.get_status()["positions"]["persisted"] is False

    _append(log, "while down\n")
    run, again = await _run(None, source)
    assert again == []  # read_from: end, as before #725


@pytest.mark.asyncio
async def test_a_save_that_fails_is_reported_once_and_tried_again(
    data_dir, log, caplog, monkeypatch
):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    run.forwarder.save_positions()
    _append(log, "one\n")
    await run.read()
    run.accept()
    real_mkstemp = position_store.tempfile.mkstemp

    def disk_full(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(position_store.tempfile, "mkstemp", disk_full)
    with caplog.at_level(logging.INFO, logger=position_store.__name__):
        assert run.forwarder.save_positions() is False
        assert run.forwarder.save_positions() is False
        status = run.forwarder.get_status()["positions"]
        monkeypatch.setattr(position_store.tempfile, "mkstemp", real_mkstemp)
        assert run.forwarder.save_positions() is True

    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "No space left on device" in errors[0]
    assert status["persisted"] is False
    assert "No space left on device" in status["problem"]
    assert run.forwarder.get_status()["positions"]["persisted"] is True
    assert _saved_offset(data_dir) == len("one\n")
    assert f"saved in {data_dir / STATE_FILE} again" in caplog.text


@pytest.mark.asyncio
async def test_no_more_files_are_remembered_than_the_bound(
    data_dir, log, glob_now, monkeypatch
):
    monkeypatch.setattr(log_forwarder, "MAX_FILES", 3)
    logs = log.parent
    source = _source(logs / "*.log", read_from="beginning")
    run = Run(data_dir, source)
    for index in range(6):
        path = logs / f"{index}.log"
        path.write_text(f"line {index}\n")
        await run.read()
        run.accept()
        # Rotated out of the pattern: no longer read, still remembered.
        os.rename(path, logs / f"{index}.old")
        await run.read()
        run.forwarder._positions_dirty = True
        run.forwarder.save_positions()
    (logs / "current.log").write_text("")
    await run.read()
    run.stop()

    files = _state(data_dir)["sources"]["app"]["files"]
    assert len(files) == 3
    assert MAX_FILES > 3
    # The one being read, and the most recent of the others.
    assert sorted(Path(entry["path"]).name for entry in files) == [
        "4.log",
        "5.log",
        "current.log",
    ]


@pytest.mark.asyncio
async def test_an_event_of_a_truncated_file_settled_late_does_not_move_the_position(
    data_dir, log
):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "a line of the old content, still in the sensor\n")
    await run.read()
    (tail,) = run.states[0].tails.values()

    os.truncate(log, 0)
    _append(log, "new\n")
    assert await run.read() == ["new"]
    run.accept("a line of the old content, still in the sensor")

    assert tail.record.offset == 0
    run.accept("new")
    assert tail.record.offset == len("new\n")


@pytest.mark.asyncio
async def test_a_truncation_takes_the_accepted_position_back_to_the_beginning(
    data_dir, log
):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "a line of the old content, accepted\n")
    await run.read()
    run.accept()

    os.truncate(log, 0)
    _append(log, "new, read and not accepted yet\n")
    await run.read()
    run.forwarder.save_positions()

    # Not the old content's offset, which would be a point in the middle of
    # the new one.
    assert _saved_offset(data_dir) == 0
    assert run.forwarder.get_status()["log_sources"][0]["positions"] == {
        str(log): {
            "read": len("new, read and not accepted yet\n"),
            "accepted": 0,
            "behind": 0,
        }
    }


@pytest.mark.asyncio
async def test_stopping_the_forwarder_writes_the_positions(data_dir, log):
    log.write_text("")
    queue = asyncio.Queue()
    forwarder = LogForwarder(_config(data_dir, _source(log)), queue)
    forwarder.poll_interval = 0.01

    await forwarder.start()
    try:
        _append(log, "one\n")
        event = await asyncio.wait_for(queue.get(), timeout=5)
        take_delivery(event).settle()
    finally:
        await forwarder.stop()

    # Not left to the periodic write, which had not come yet.
    assert _saved_offset(data_dir) == len("one\n")


@pytest.mark.asyncio
async def test_the_status_shows_how_far_each_file_was_read_and_accepted(data_dir, log):
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "one\ntwo\n")
    await run.read()
    run.accept("one")
    run.forwarder.save_positions()

    status = run.forwarder.get_status()

    assert status["log_sources"][0]["positions"] == {
        str(log): {"read": len("one\ntwo\n"), "accepted": len("one\n"), "behind": 0}
    }
    assert status["positions"]["persisted"] is True
    assert status["positions"]["file"] == str(data_dir / STATE_FILE)
    assert status["positions"]["problem"] is None
    assert status["positions"]["last_saved"]


@pytest.mark.asyncio
async def test_the_status_shows_how_far_behind_a_file_is(data_dir, log):
    # A log written faster than the sensor delivers: what waits is in the
    # file, and the status says how much.
    log.write_text("")
    source = _source(log)
    run, _ = await _run(data_dir, source)
    _append(log, "one\ntwo\n")
    await run.read()
    _append(log, "written, and not read yet\n")

    (positions,) = run.forwarder.get_status()["log_sources"][0]["positions"].values()

    assert positions["read"] == len("one\ntwo\n")
    assert positions["behind"] == len("written, and not read yet\n")
    await run.read()
    (positions,) = run.forwarder.get_status()["log_sources"][0]["positions"].values()
    assert positions["behind"] == 0


# -- the real pipeline ------------------------------------------------------


class Pipeline:
    """The forwarder, the processor and the sender, started as the agent
    starts them; the gateway is ``answer``."""

    def __init__(self, data_dir, source, monkeypatch):
        self.config = _config(
            data_dir, source, api_key=API_KEY, batch_size=2, flush_interval=1
        )
        self.accepted = []
        self.answer = SENT
        collected, processed = asyncio.Queue(maxsize=50), asyncio.Queue(maxsize=50)
        self.logs = LogForwarder(self.config, collected)
        self.logs.poll_interval = 0.01
        self.processor = DataProcessor(self.config, collected, processed)
        self.sender = DataForwarder(self.config, processed)
        self.sender.min_request_interval = 0.002
        monkeypatch.setattr(log_forwarder, "POSITION_SAVE_INTERVAL", 0.02)

        async def no_session():
            self.sender.session = None

        async def send(body):
            if self.answer == SENT:
                self.accepted += [
                    event["event_data"]["data"]["raw_message"]
                    for event in json.loads(body)["events"]
                ]
            return self.answer

        self.sender._init_session = no_session
        self.sender._send = send

    async def start(self):
        await self.processor.start()
        await self.sender.start()
        await self.logs.start()

    async def stop(self):
        await self.logs.stop()
        await self.processor.stop()
        await self.sender.stop()
        self.logs.save_positions()


async def _until(condition, timeout=10):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


@pytest.mark.asyncio
async def test_the_position_follows_what_the_gateway_accepts(
    data_dir, log, monkeypatch
):
    log.write_text("")
    source = _source(log)
    pipeline = Pipeline(data_dir, source, monkeypatch)
    monkeypatch.setattr(data_forwarder, "STOP_FLUSH_SECONDS", 0.5)

    await pipeline.start()
    try:
        _append(log, "one\ntwo\n")
        await _until(lambda: pipeline.accepted == ["one", "two"])
        # Written by the periodic save, not by a stop.
        await _until(
            lambda: (data_dir / STATE_FILE).exists()
            and _saved_offset(data_dir) == len("one\ntwo\n")
        )

        # The gateway stops answering: lines are read and wait in the
        # sender's buffer; the position stays where it is.
        pipeline.answer = RETRY
        _append(log, "three\nfour\n")
        await _until(lambda: len(pipeline.sender.buffer) == 2)
        await _until(lambda: pipeline.sender.failures >= 1)
        status = pipeline.logs.get_status()["log_sources"][0]["positions"][str(log)]
        assert status == {
            "read": len("one\ntwo\nthree\nfour\n"),
            "accepted": len("one\ntwo\n"),
            "behind": 0,
        }
    finally:
        await pipeline.stop()

    assert _saved_offset(data_dir) == len("one\ntwo\n")
    # Unsent, but not lost: their source reads them again.
    assert pipeline.sender.stats["events_returned_to_source"] == 2
    assert pipeline.sender.stats["events_dropped"] == 0

    # The sensor starts again and the gateway is back.
    again = Pipeline(data_dir, source, monkeypatch)
    await again.start()
    try:
        await _until(lambda: again.accepted == ["three", "four"])
    finally:
        await again.stop()

    assert _saved_offset(data_dir) == len("one\ntwo\nthree\nfour\n")


@pytest.mark.asyncio
async def test_a_refused_batch_moves_the_position_its_lines_are_dropped_for_good(
    data_dir, log, monkeypatch
):
    log.write_text("")
    source = _source(log)
    pipeline = Pipeline(data_dir, source, monkeypatch)
    pipeline.answer = data_forwarder.REFUSED

    await pipeline.start()
    try:
        _append(log, "one\ntwo\n")
        await _until(lambda: pipeline.sender.stats["events_dropped_refused"] == 2)
    finally:
        await pipeline.stop()

    assert _saved_offset(data_dir) == len("one\ntwo\n")


@pytest.mark.asyncio
async def test_the_agent_saves_what_its_last_batches_delivered(
    data_dir, log, monkeypatch
):
    # Stopping: the collectors first, then the sender's last batches, then
    # the positions once more. Saved before those batches, the lines they
    # deliver would be sent again after the restart.
    log.write_text("")
    config = _config(
        data_dir, _source(log), api_key=API_KEY, batch_size=100, flush_interval=3600
    )
    accepted = []

    async def send(self, body):
        accepted.extend(
            event["event_data"]["data"]["raw_message"]
            for event in json.loads(body)["events"]
        )
        return SENT

    class Session:
        closed = False

        async def close(self):
            self.closed = True

    async def session(self):
        self.session = Session()

    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(DataForwarder, "_send", send)
    monkeypatch.setattr(log_forwarder, "POLL_INTERVAL", 0.01)
    agent = SecuritySensorAgent(config)

    await agent.start()
    try:
        _append(log, "one\ntwo\nthree\n")
        await _until(lambda: len(agent.data_forwarder.buffer) == 3)
        assert accepted == []
    finally:
        await agent.stop()

    assert accepted == ["one", "two", "three"]
    assert _saved_offset(data_dir) == len("one\ntwo\nthree\n")


def _stand_in_gateway(monkeypatch, answer):
    """The sender of every agent answers ``answer()``; the lines accepted."""
    accepted = []

    class Session:
        closed = False

        async def close(self):
            self.closed = True

    async def session(self):
        self.session = Session()

    async def send(self, body):
        outcome = answer()
        if outcome == SENT:
            accepted.extend(
                event["event_data"]["data"]["raw_message"]
                for event in json.loads(body)["events"]
            )
        return outcome

    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(DataForwarder, "_send", send)
    monkeypatch.setattr(log_forwarder, "POLL_INTERVAL", 0.01)
    return accepted


def _collected(message):
    """An event as a collector that cannot read it again would queue it."""
    return {"type": "file_created", "source": "fim", "data": {"raw_message": message}}


@pytest.mark.asyncio
async def test_what_was_collected_just_before_the_stop_still_reaches_the_gateway(
    data_dir, log, monkeypatch
):
    # Stopping the pipeline under the events still in its queues dropped
    # them without a word.
    log.write_text("")
    accepted = _stand_in_gateway(monkeypatch, lambda: SENT)
    agent = SecuritySensorAgent(
        _config(data_dir, _source(log), api_key=API_KEY, batch_size=100)
    )
    process = DataProcessor._process_single_event

    async def slowly(self, event):
        # Long enough for the collectors to have stopped meanwhile: the
        # events are in the queue, and then in the workers' hands.
        await asyncio.sleep(0.3)
        return await process(self, event)

    monkeypatch.setattr(DataProcessor, "_process_single_event", slowly)

    await agent.start()
    for index in range(9):
        agent.event_queue.put_nowait(_collected(f"event {index}"))
    await agent.stop()

    assert sorted(accepted) == [f"event {index}" for index in range(9)]
    assert agent.data_forwarder.stats["events_forwarded"] == 9
    assert agent.data_processor.in_flight == 0
    assert agent.event_queue.empty() and agent.processed_queue.empty()


@pytest.mark.asyncio
async def test_what_cannot_reach_the_sender_at_the_stop_is_counted_and_said(
    data_dir, log, monkeypatch, caplog
):
    from sensor.core import agent as agent_module

    log.write_text("")
    _stand_in_gateway(monkeypatch, lambda: RETRY)
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 0.1)
    monkeypatch.setattr(data_forwarder, "STOP_FLUSH_SECONDS", 0.5)
    agent = SecuritySensorAgent(
        _config(
            data_dir, _source(log), api_key=API_KEY, batch_size=2, buffer_max_events=2
        )
    )

    from sensor.pipeline.delivery import DELIVERY_KEY, Delivery

    await agent.start()
    agent.data_forwarder.min_request_interval = 0.002
    for index in range(7):
        agent.event_queue.put_nowait(_collected(f"event {index}"))
    # The sender holds two and has a third in hand; the rest waits behind.
    await _until(lambda: agent.data_forwarder.get_status()["buffer"]["full"])
    # And one more, from a log file whose position is kept.
    line = _collected("a line of a log")
    line[DELIVERY_KEY] = Delivery(lambda: None, replayable=True)
    agent.event_queue.put_nowait(line)
    with caplog.at_level(logging.WARNING):
        await agent.stop()

    stats = agent.data_forwarder.stats
    assert stats["events_dropped_shutdown"] == 3
    assert (
        "Stopped with 5 events still on their way to the sender: 4 are "
        "dropped, 1 will be read again from their log source after the restart"
    ) in caplog.text
    assert agent.event_queue.empty() and agent.processed_queue.empty()


@pytest.mark.asyncio
async def test_an_event_the_processor_filters_is_settled_and_carries_no_handle(
    data_dir, log
):
    collected, processed = asyncio.Queue(), asyncio.Queue()
    processor = DataProcessor(_config(data_dir), collected, processed)
    settled = []
    from sensor.pipeline.delivery import DELIVERY_KEY, Delivery

    def event(name, data):
        return {
            "type": "log.app",
            "source": "log_forwarder",
            "data": data,
            DELIVERY_KEY: Delivery(lambda: settled.append(name)),
        }

    await processor.start()
    try:
        await collected.put(event("kept", {"raw_message": "a line"}))
        await collected.put(event("filtered", {}))  # no data: filtered
        kept = await asyncio.wait_for(processed.get(), timeout=5)
        await _until(lambda: processor.stats["events_filtered"] == 1)
    finally:
        await processor.stop()

    # Filtered: finished with. Kept: carried on, outside what is sent.
    assert settled == ["filtered"]
    delivery = take_delivery(kept)
    assert DELIVERY_KEY not in kept and "_delivery" not in json.dumps(kept)
    delivery.settle()
    delivery.settle()  # once only
    assert settled == ["filtered", "kept"]
