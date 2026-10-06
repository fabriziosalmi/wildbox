"""The file monitor's saved baseline is read without trust (#745).

``fim-baseline.json`` decides what the monitor reports when it starts: a
file whose entry matches is not a change. It is written by the sensor and
read back by it, and what is read must be what this sensor, with these
settings, would have written: anything else and the whole file is ignored,
which is the monitor's behavior before there was a file.
"""

import copy
import json
import logging
import os
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors import baseline_store  # noqa: E402
from sensor.collectors.baseline_store import (  # noqa: E402
    BASELINE_FILE,
    BaselineStore,
    under,
)
from sensor.utils import state_file  # noqa: E402

WATCH = {"exclude_patterns": ["*.tmp"], "max_depth": 10, "max_files": 50000}
DIGEST = "a" * 64


def _state(path, **changes):
    state = {
        "path": path,
        "size": 12,
        "mtime": 1790000000.25,
        "ctime": 1790000001.5,
        "mode": 0o100644,
        "uid": 0,
        "gid": 0,
        "hash": DIGEST,
    }
    state.update(changes)
    return state


FILES = {
    "/host/etc/hosts": _state("/host/etc/hosts"),
    "/host/etc/shadow": _state("/host/etc/shadow", hash=None, mode=0o100000),
    "/host/etc/ssh/sshd_config": _state(
        "/host/etc/ssh/sshd_config", uid=None, gid=None
    ),
}
ROOTS = ["/host/etc"]


def _saved(directory):
    return json.loads((directory / BASELINE_FILE).read_text())


def _write(directory, document):
    (directory / BASELINE_FILE).write_text(json.dumps(document))


def _document(tmp_path):
    """A baseline as this sensor writes it."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    assert BaselineStore(str(elsewhere)).save(WATCH, ROOTS, FILES)
    return _saved(elsewhere)


def test_what_is_saved_is_what_is_loaded(tmp_path):
    store = BaselineStore(str(tmp_path))

    assert store.save(WATCH, ROOTS, FILES) is True
    saved_at, roots, files = BaselineStore(str(tmp_path)).load(WATCH)

    assert roots == ROOTS
    assert files == FILES
    assert saved_at == store.last_saved
    assert store.get_status() == {
        "persisted": True,
        "file": str(tmp_path / BASELINE_FILE),
        "loaded": None,
        "last_saved": saved_at,
        "problem": None,
    }


def test_the_file_holds_no_content_and_nothing_but_what_is_compared(tmp_path):
    BaselineStore(str(tmp_path)).save(WATCH, ROOTS, FILES)

    document = _saved(tmp_path)

    assert sorted(document) == [
        "files",
        "format",
        "roots",
        "saved_at",
        "version",
        "watch",
    ]
    assert document["format"] == "wildbox-sensor-fim-baseline"
    assert document["version"] == 1
    assert document["watch"] == WATCH
    assert document["roots"] == ROOTS
    assert document["files"]["/host/etc/hosts"] == {
        "size": 12,
        "mtime": 1790000000.25,
        "ctime": 1790000001.5,
        "mode": 0o100644,
        "uid": 0,
        "gid": 0,
        "hash": DIGEST,
    }
    assert (tmp_path / BASELINE_FILE).stat().st_mode & 0o777 == 0o600


def test_without_a_file_there_is_no_baseline_and_it_is_not_a_warning(tmp_path, caplog):
    store = BaselineStore(str(tmp_path))

    with caplog.at_level(logging.INFO, logger=baseline_store.__name__):
        assert store.load(WATCH) is None

    assert [r.levelname for r in caplog.records] == ["INFO"]
    assert "No saved file monitor baseline" in caplog.text
    assert store.get_status()["loaded"] == "none was saved yet"


def test_without_a_directory_nothing_is_kept_and_the_status_says_so():
    store = BaselineStore(None)

    assert store.persistent is False
    assert store.load(WATCH) is None
    assert store.save(WATCH, ROOTS, FILES) is False
    status = store.get_status()
    assert status["persisted"] is False
    assert status["file"] is None
    assert status["problem"] == (
        "data_dir is not set: the baseline is kept in memory only, and what "
        "changes while the sensor is stopped is not reported"
    )


def _set(path, value):
    def change(document):
        target = document
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return change


def _drop(path):
    def change(document):
        target = document
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]

    return change


HOSTS = ("files", "/host/etc/hosts")
# A state as the file holds it: valid wherever it is put.
STORED = {
    key: value for key, value in FILES["/host/etc/hosts"].items() if key != "path"
}

NOT_WRITTEN_BY_THIS_SENSOR = {
    "not a mapping": lambda document: ["a", "list"],
    "another format": _set(("format",), "wildbox-sensor-log-positions"),
    "another version": _set(("version",), 2),
    "a version that is true": _set(("version",), True),
    "no watch": _drop(("watch",)),
    "one key more": _set(("extra",), 1),
    "saved_at is not text": _set(("saved_at",), 5),
    "roots is not a list": _set(("roots",), "/host/etc"),
    "a root that is not absolute": _set(("roots",), ["host/etc"]),
    "a root twice": _set(("roots",), ["/host/etc", "/host/etc"]),
    "a root with a NUL": _set(("roots",), ["/host/etc\x00"]),
    "files is not a mapping": _set(("files",), []),
    "a file under no root": _set(("files", "/root/.ssh/authorized_keys"), STORED),
    "a file beside a root": _set(("files", "/host/etc2/hosts"), STORED),
    "a path that is not absolute": _set(("files", "etc/hosts"), STORED),
    "a state that is not a mapping": _set(HOSTS, [12, 0]),
    "a state without its hash": _drop(HOSTS + ("hash",)),
    "a state with one key more": _set(HOSTS + ("content",), "root:x:0:0"),
    "a hash that is not a digest": _set(HOSTS + ("hash",), "abc"),
    "a hash of another length": _set(HOSTS + ("hash",), "a" * 63),
    "a size that is text": _set(HOSTS + ("size",), "12"),
    "a negative size": _set(HOSTS + ("size",), -1),
    "a size that is true": _set(HOSTS + ("size",), True),
    "a time that is text": _set(HOSTS + ("mtime",), "yesterday"),
    "a time that is not a number": _set(HOSTS + ("ctime",), float("nan")),
    "a time out of range": _set(HOSTS + ("mtime",), 1e300),
    "a mode out of range": _set(HOSTS + ("mode",), 2**40),
    "an owner that is text": _set(HOSTS + ("uid",), "root"),
    "a group out of range": _set(HOSTS + ("gid",), -5),
    "patterns that are not a list": _set(("watch", "exclude_patterns"), "*.tmp"),
    "a pattern that is not text": _set(("watch", "exclude_patterns"), [5]),
    "a depth that is text": _set(("watch", "max_depth"), "10"),
    "more files than max_files": _set(("watch", "max_files"), 2),
}


@pytest.mark.parametrize("what", sorted(NOT_WRITTEN_BY_THIS_SENSOR))
def test_a_file_this_sensor_would_not_have_written_is_ignored_whole(
    tmp_path, caplog, what
):
    document = _document(tmp_path)
    changed = NOT_WRITTEN_BY_THIS_SENSOR[what](document)
    _write(tmp_path, document if changed is None else changed)
    store = BaselineStore(str(tmp_path))
    watch = WATCH
    if what == "more files than max_files":
        # The settings match, and the file holds more than they allow.
        watch = dict(WATCH, max_files=2)

    with caplog.at_level(logging.WARNING, logger=baseline_store.__name__):
        loaded = store.load(watch)

    assert loaded is None, what
    (warning,) = [r.getMessage() for r in caplog.records]
    assert warning.startswith(
        f"The saved file monitor baseline {tmp_path / BASELINE_FILE} is ignored: "
    )
    assert "a change made while the sensor was stopped is not reported" in warning
    assert store.get_status()["loaded"].startswith("ignored: ")


def test_the_document_the_broken_ones_are_made_from_is_accepted(tmp_path):
    document = _document(tmp_path)
    # With one more file, as the broken ones add theirs.
    document["files"]["/host/etc/issue"] = STORED
    _write(tmp_path, document)

    _, roots, files = BaselineStore(str(tmp_path)).load(WATCH)

    assert roots == ROOTS
    assert files == dict(FILES, **{"/host/etc/issue": _state("/host/etc/issue")})


@pytest.mark.parametrize(
    "raw", [b"", b"{", b"\xff\xfe", b"null", b"[" * 100000, b'{"format": NaN}']
)
def test_what_is_not_json_is_ignored(tmp_path, caplog, raw):
    (tmp_path / BASELINE_FILE).write_bytes(raw)

    with caplog.at_level(logging.WARNING, logger=baseline_store.__name__):
        assert BaselineStore(str(tmp_path)).load(WATCH) is None

    assert len(caplog.records) == 1


@pytest.mark.parametrize(
    "setting, value",
    [
        ("exclude_patterns", ["*.tmp", "*.log"]),
        ("exclude_patterns", []),
        ("max_depth", 3),
        ("max_files", 100),
    ],
)
def test_a_baseline_taken_with_other_settings_is_not_compared_with(
    tmp_path, caplog, setting, value
):
    # With other exclusions or another depth, files enter and leave what is
    # watched: against the old baseline each would be a creation or a
    # deletion that never happened.
    BaselineStore(str(tmp_path)).save(WATCH, ROOTS, FILES)
    store = BaselineStore(str(tmp_path))

    with caplog.at_level(logging.WARNING, logger=baseline_store.__name__):
        loaded = store.load(dict(WATCH, **{setting: value}))

    assert loaded is None
    (warning,) = [r.getMessage() for r in caplog.records]
    assert "was taken with other fim settings" in warning
    assert store.get_status()["loaded"] == (
        "ignored: the fim settings have changed since"
    )


def test_an_older_picture_is_not_written_over_a_newer_one(tmp_path):
    store = BaselineStore(str(tmp_path))
    older, newer = store.next_serial(), store.next_serial()
    one = {"/host/etc/hosts": FILES["/host/etc/hosts"]}

    assert store.save(WATCH, ROOTS, FILES, newer) is True
    # The write made in a worker thread reaches the disk after the one made
    # at stop: it is not an error, and it changes nothing.
    assert store.save(WATCH, ROOTS, one, older) is True

    assert sorted(_saved(tmp_path)["files"]) == sorted(FILES)


def test_a_save_that_fails_is_said_once_and_the_next_one_that_works_too(
    tmp_path, monkeypatch, caplog
):
    store = BaselineStore(str(tmp_path))
    store.save(WATCH, ROOTS, FILES)
    before = (tmp_path / BASELINE_FILE).read_bytes()
    real_replace = os.replace

    def no_rename(source, target):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(state_file.os, "replace", no_rename)
    with caplog.at_level(logging.INFO, logger=baseline_store.__name__):
        assert store.save(WATCH, ROOTS, {}) is False
        assert store.save(WATCH, ROOTS, {}) is False
        failed = store.get_status()
        monkeypatch.setattr(state_file.os, "replace", real_replace)
        assert store.save(WATCH, ROOTS, {}) is True

    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert errors[0].startswith(
        f"the file monitor baseline cannot be saved in {tmp_path}: "
        f"No space left on device. Until it works"
    )
    assert failed["persisted"] is False
    assert failed["problem"] == (
        f"the file monitor baseline cannot be saved in {tmp_path}: "
        f"No space left on device"
    )
    assert "The file monitor baseline is saved" in caplog.text
    assert store.get_status()["persisted"] is True
    assert (tmp_path / BASELINE_FILE).read_bytes() != before
    assert os.listdir(tmp_path) == [BASELINE_FILE]


def test_a_baseline_larger_than_its_file_may_be_is_not_written(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline_store, "MAX_BASELINE_BYTES", 600)
    store = BaselineStore(str(tmp_path))
    one = {"/host/etc/hosts": FILES["/host/etc/hosts"]}
    assert store.save(WATCH, ROOTS, one) is True

    assert store.save(WATCH, ROOTS, FILES) is False

    assert "more than the file may hold (600)" in store.get_status()["problem"]
    assert sorted(_saved(tmp_path)["files"]) == ["/host/etc/hosts"]


def test_a_name_that_is_not_text_a_file_system_gives_is_kept_as_it_is(tmp_path):
    # os.listdir gives the bytes of such a name as surrogates.
    name = "/host/etc/caf\udce9"
    files = {name: _state(name)}

    BaselineStore(str(tmp_path)).save(WATCH, ROOTS, files)
    _, _, loaded = BaselineStore(str(tmp_path)).load(WATCH)

    assert loaded == files


@pytest.mark.parametrize(
    "path, root, answer",
    [
        ("/etc", "/etc", True),
        ("/etc/hosts", "/etc", True),
        ("/etc/ssh/sshd_config", "/etc", True),
        ("/etc2/hosts", "/etc", False),
        ("/etc-backup", "/etc", False),
        ("/et", "/etc", False),
        ("/etc/hosts", "/", True),
        ("/etc/hosts", "/etc/", True),
        ("/etc/hosts", "/etc/hosts", True),
        ("/etc/hosts.bak", "/etc/hosts", False),
    ],
)
def test_under(path, root, answer):
    assert under(path, root) is answer


def test_the_baseline_and_the_positions_share_a_directory(tmp_path):
    from sensor.collectors.position_store import STATE_FILE, PositionStore

    positions = PositionStore(str(tmp_path))
    baseline = BaselineStore(str(tmp_path))
    positions.save({})
    baseline.save(WATCH, ROOTS, FILES)

    # Each reads its own file, and leaves the other's alone.
    assert PositionStore(str(tmp_path)).load() == {}
    assert BaselineStore(str(tmp_path)).load(WATCH)[2] == FILES
    assert sorted(os.listdir(tmp_path)) == sorted([STATE_FILE, BASELINE_FILE])


def test_a_copy_of_the_document_is_not_changed_by_validating_it(tmp_path):
    document = _document(tmp_path)
    kept = copy.deepcopy(document)

    baseline_store.validate_baseline(document)

    assert document == kept
