"""The file that keeps the log forwarder's positions is written whole and read
with suspicion (#725).

It decides which lines the sensor does not send again, so what is read from
it is checked value by value: anything this sensor would not have written and
the whole file is ignored, with a warning, never used in part.
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

from sensor.collectors import position_store  # noqa: E402
from sensor.collectors.position_store import (  # noqa: E402
    MAX_FILES,
    MAX_SOURCES,
    MAX_STATE_BYTES,
    STATE_FILE,
    PositionStore,
    data_dir_problem,
    file_entries,
)
from sensor.core.config import DataLakeConfig, SensorConfig, load_config  # noqa: E402

DIGEST = "ab" * 32


def _file(**changes):
    entry = {
        "device": 2049,
        "inode": 131077,
        "offset": 4096,
        "check": DIGEST,
        "head_bytes": 256,
        "head": DIGEST,
        "path": "/var/log/nginx/access.log",
        "seen": 1790000000.5,
    }
    entry.update(changes)
    return entry


def _sources():
    return {
        "nginx_access": {
            "type": "file",
            "path": "/var/log/nginx/access.log*",
            "files": [_file(), _file(inode=131078, path="/var/log/nginx/access.log.1")],
        },
        "journal": {"type": "journald", "cursor": "s=0a1b;i=2f;b=77;m=9;t=5e;x=c1"},
        "security": {"type": "windows_event", "log_name": "Security", "record_id": 42},
    }


def _document(sources=None):
    return {
        "format": "wildbox-sensor-log-positions",
        "version": 1,
        "saved_at": "2026-10-05T10:00:00+00:00",
        "sources": _sources() if sources is None else sources,
    }


def _write(directory, document):
    content = document if isinstance(document, bytes) else json.dumps(document).encode()
    (directory / STATE_FILE).write_bytes(content)


def _ignored(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and "are ignored" in record.getMessage()
    ]


def test_what_is_saved_is_what_is_loaded(tmp_path):
    store = PositionStore(str(tmp_path))

    assert store.save(_sources()) is True

    assert PositionStore(str(tmp_path)).load() == _sources()
    assert store.get_status()["persisted"] is True
    assert store.get_status()["last_saved"]
    assert file_entries(_sources(), "nginx_access", "/var/log/nginx/access.log*")
    # Another path under the same name, another type, or no such source:
    # not the source that was saved.
    assert file_entries(_sources(), "nginx_access", "/srv/other.log") is None
    assert file_entries(_sources(), "journal", "/var/log/journal") is None
    assert file_entries(_sources(), "absent", "/var/log/x") is None


def test_no_file_yet_is_not_a_problem(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger=position_store.__name__):
        assert PositionStore(str(tmp_path)).load() == {}

    assert caplog.records == []


def test_a_save_replaces_the_file_and_never_leaves_half_of_one(tmp_path, monkeypatch):
    store = PositionStore(str(tmp_path))
    store.save(_sources())
    before = (tmp_path / STATE_FILE).read_bytes()
    steps = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        steps.append("fsync")
        real_fsync(fd)

    def replace(source, target):
        # The new content is complete and on disk under another name; the
        # old file is untouched until this very call.
        steps.append("rename")
        assert (tmp_path / STATE_FILE).read_bytes() == before
        assert json.loads(Path(source).read_bytes())["sources"] == {}
        assert Path(source).parent == tmp_path
        real_replace(source, target)

    monkeypatch.setattr(position_store.os, "fsync", fsync)
    monkeypatch.setattr(position_store.os, "replace", replace)

    assert store.save({}) is True

    # The data, then the name, then the directory that holds the name.
    assert steps == ["fsync", "rename", "fsync"]
    assert PositionStore(str(tmp_path)).load() == {}
    assert os.listdir(tmp_path) == [STATE_FILE]


def test_an_older_picture_is_not_written_over_a_newer_one(tmp_path):
    # While the sensor runs the positions are written from a worker thread;
    # at stop, from the event loop. The thread's write may come last.
    store = PositionStore(str(tmp_path))
    older, newer = store.next_serial(), store.next_serial()
    journal = _sources()["journal"]

    assert store.save({"newer": journal}, newer) is True
    assert store.save({"older": journal}, older) is True  # nothing to do

    assert set(PositionStore(str(tmp_path)).load()) == {"newer"}
    assert store.save({"latest": journal}, store.next_serial()) is True
    assert set(PositionStore(str(tmp_path)).load()) == {"latest"}


def test_a_save_that_fails_keeps_the_old_file_and_leaves_no_temporary_one(
    tmp_path, monkeypatch
):
    store = PositionStore(str(tmp_path))
    store.save(_sources())

    def no_rename(source, target):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(position_store.os, "replace", no_rename)

    assert store.save({}) is False

    assert "Read-only file system" in store.problem
    assert store.get_status()["persisted"] is False
    assert os.listdir(tmp_path) == [STATE_FILE]
    assert PositionStore(str(tmp_path)).load() == _sources()


def test_temporary_files_a_crash_left_are_removed(tmp_path):
    (tmp_path / ".log-positions.abc123.tmp").write_text("{half a docu")
    (tmp_path / "unrelated.tmp").write_text("not the sensor's")
    PositionStore(str(tmp_path)).save(_sources())

    assert PositionStore(str(tmp_path)).load() == _sources()

    assert sorted(os.listdir(tmp_path)) == [STATE_FILE, "unrelated.tmp"]


def _broken(change):
    document = _document()
    change(document)
    return document


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


FILE0 = ("sources", "nginx_access", "files", 0)

NOT_WRITTEN_BY_THIS_SENSOR = {
    "another format": _set(("format",), "filebeat-registry"),
    "a later version": _set(("version",), 2),
    "version true": _set(("version",), True),
    "no version": _drop(("version",)),
    "an extra top-level key": _set(("comment",), "x"),
    "sources a list": _set(("sources",), []),
    "a source name no configuration allows": _set(
        ("sources", "../etc"), _sources()["journal"]
    ),
    "a source that is a string": _set(("sources", "nginx_access"), "x"),
    "an unknown source type": _set(("sources", "journal", "type"), "tcp"),
    "an extra source key": _set(("sources", "journal", "since"), "yesterday"),
    "files not a list": _set(("sources", "nginx_access", "files"), {}),
    "source path not a string": _set(("sources", "nginx_access", "path"), 5),
    "a negative offset": _set(FILE0 + ("offset",), -1),
    "an offset that is text": _set(FILE0 + ("offset",), "4096"),
    "an offset that is true": _set(FILE0 + ("offset",), True),
    "a fractional offset": _set(FILE0 + ("offset",), 4096.5),
    "an offset beyond 63 bits": _set(FILE0 + ("offset",), 2**63),
    "a digest that is not one": _set(FILE0 + ("check",), "abc"),
    "an uppercase digest": _set(FILE0 + ("head",), "AB" * 32),
    "more head bytes than are hashed": _set(FILE0 + ("head_bytes",), 257),
    "a negative inode": _set(FILE0 + ("inode",), -5),
    "a missing device": _drop(FILE0 + ("device",)),
    "an extra file key": _set(FILE0 + ("mode",), 420),
    "a path with a NUL": _set(FILE0 + ("path",), "/var/log/a\x00b"),
    "a path that is too long": _set(FILE0 + ("path",), "/" + "a" * 5000),
    "seen not a number": _set(FILE0 + ("seen",), "now"),
    "seen NaN": _set(FILE0 + ("seen",), float("nan")),
    "the same file twice": _set(
        ("sources", "nginx_access", "files"), [_file(), _file()]
    ),
    "a cursor that could be an option": _set(
        ("sources", "journal", "cursor"), "--file=/etc/shadow"
    ),
    "a cursor with a space": _set(("sources", "journal", "cursor"), "s=1 --all"),
    "an empty cursor": _set(("sources", "journal", "cursor"), ""),
    "a log name with a quote": _set(
        ("sources", "security", "log_name"), 'Security"; Remove-Item'
    ),
    "a negative record id": _set(("sources", "security", "record_id"), -1),
    "a record id that is text": _set(("sources", "security", "record_id"), "42"),
}


@pytest.mark.parametrize("what", sorted(NOT_WRITTEN_BY_THIS_SENSOR))
def test_a_value_this_sensor_would_not_write_voids_the_whole_file(
    tmp_path, caplog, what
):
    _write(tmp_path, _broken(NOT_WRITTEN_BY_THIS_SENSOR[what]))

    with caplog.at_level(logging.WARNING, logger=position_store.__name__):
        loaded = PositionStore(str(tmp_path)).load()

    # Not the valid part of it: nothing.
    assert loaded == {}
    assert len(_ignored(caplog)) == 1


def test_too_many_sources_or_files_void_the_file(tmp_path, caplog):
    many_files = _document()
    many_files["sources"]["nginx_access"]["files"] = [
        _file(inode=index) for index in range(MAX_FILES + 1)
    ]
    many_sources = _document(
        {f"source-{index}": _sources()["journal"] for index in range(MAX_SOURCES + 1)}
    )
    at_the_bounds = _document(
        {
            f"source-{index}": {
                "type": "file",
                "path": "/var/log/app.log",
                "files": [_file(inode=inode) for inode in range(MAX_FILES)],
            }
            for index in range(MAX_SOURCES)
        }
    )

    with caplog.at_level(logging.WARNING, logger=position_store.__name__):
        _write(tmp_path, many_files)
        assert PositionStore(str(tmp_path)).load() == {}
        _write(tmp_path, many_sources)
        assert PositionStore(str(tmp_path)).load() == {}
        assert len(_ignored(caplog)) == 2

        # The most this sensor writes is read back, and fits the size limit.
        _write(tmp_path, at_the_bounds)
        assert len(PositionStore(str(tmp_path)).load()) == MAX_SOURCES
        assert len(_ignored(caplog)) == 2
    assert (tmp_path / STATE_FILE).stat().st_size < MAX_STATE_BYTES


def test_a_file_larger_than_the_limit_is_not_even_parsed(tmp_path, caplog, monkeypatch):
    monkeypatch.setattr(position_store, "MAX_STATE_BYTES", 2000)
    document = _document()
    document["saved_at"] = "x" * 3000
    _write(tmp_path, document)
    parsed = []
    monkeypatch.setattr(position_store.json, "loads", parsed.append)

    with caplog.at_level(logging.WARNING, logger=position_store.__name__):
        assert PositionStore(str(tmp_path)).load() == {}

    assert parsed == []
    assert "more than a position file holds" in _ignored(caplog)[0]


def test_a_link_is_not_followed(tmp_path, caplog):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _write(elsewhere, _document())
    data = tmp_path / "data"
    data.mkdir()
    os.symlink(elsewhere / STATE_FILE, data / STATE_FILE)

    with caplog.at_level(logging.WARNING, logger=position_store.__name__):
        assert PositionStore(str(data)).load() == {}

    assert len(_ignored(caplog)) == 1


def test_something_that_is_not_a_regular_file_is_not_read(tmp_path, caplog):
    (tmp_path / STATE_FILE).mkdir()
    fifo = tmp_path / "fifo"
    fifo.mkdir()
    os.mkfifo(fifo / STATE_FILE)

    with caplog.at_level(logging.WARNING, logger=position_store.__name__):
        assert PositionStore(str(tmp_path)).load() == {}
        assert PositionStore(str(fifo)).load() == {}  # and does not block

    assert len(_ignored(caplog)) == 2


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="no user ids here")
def test_a_file_of_another_user_is_not_trusted(tmp_path, caplog, monkeypatch):
    _write(tmp_path, _document())
    monkeypatch.setattr(position_store.os, "geteuid", lambda: os.getuid() + 1)

    with caplog.at_level(logging.WARNING, logger=position_store.__name__):
        assert PositionStore(str(tmp_path)).load() == {}

    assert "not to the sensor's user" in _ignored(caplog)[0]


def test_without_a_directory_nothing_is_read_or_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = PositionStore(None)

    assert store.persistent is False
    assert store.load() == {}
    assert store.save(_sources()) is False
    assert os.listdir(tmp_path) == []
    assert store.get_status() == {
        "persisted": False,
        "file": None,
        "last_saved": None,
        "problem": "data_dir is not set: positions are kept in memory only",
    }


# -- data_dir in the configuration -----------------------------------------


def _config(data_dir):
    return SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        data_dir=data_dir,
    )


def test_a_data_directory_must_exist_and_be_writable(tmp_path):
    assert _config(None).validate() == []
    assert _config(str(tmp_path)).validate() == []
    assert data_dir_problem(str(tmp_path)) is None

    (missing,) = _config(str(tmp_path / "absent")).validate()
    assert "does not exist or is not a directory" in missing
    (relative,) = _config("var/lib/sensor").validate()
    assert "must be an absolute path" in relative
    a_file = tmp_path / "file"
    a_file.write_text("")
    assert "is not a directory" in _config(str(a_file)).validate()[0]
    assert "must be a path" in _config(5).validate()[0]


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="root writes a directory whatever its mode",
)
def test_a_data_directory_the_sensor_cannot_write_stops_it(tmp_path):
    read_only = tmp_path / "data"
    read_only.mkdir()
    read_only.chmod(0o555)

    try:
        (problem,) = _config(str(read_only)).validate()
    finally:
        read_only.chmod(0o755)

    assert f"is not writable by the sensor's user (uid {os.geteuid()})" in problem


def test_data_dir_comes_from_the_file_or_the_environment(tmp_path, monkeypatch):
    in_file = tmp_path / "from-file"
    in_env = tmp_path / "from-env"
    in_file.mkdir()
    in_env.mkdir()
    config_path = tmp_path / "config.yaml"

    def loaded(text):
        config_path.write_text('data_lake:\n  endpoint: "https://gw"\n' + text)
        return load_config(str(config_path)).data_dir

    monkeypatch.delenv("SENSOR_DATA_DIR", raising=False)
    assert loaded("") is None
    assert loaded('data_dir: ""\n') is None
    assert loaded(f"data_dir: {in_file}\n") == str(in_file)
    monkeypatch.setenv("SENSOR_DATA_DIR", str(in_env))
    assert loaded(f"data_dir: {in_file}\n") == str(in_env)
    monkeypatch.setenv("SENSOR_DATA_DIR", str(tmp_path / "absent"))
    with pytest.raises(ValueError, match="does not exist or is not a directory"):
        loaded("")


def test_the_shipped_container_configurations_keep_positions_in_the_data_volume():
    import yaml

    for name in ("config.yaml.example", "config.docker.yaml"):
        settings = yaml.safe_load((SERVICE_ROOT / name).read_text())
        assert settings["data_dir"] == "/var/lib/security-sensor", name
    # The directory the image creates for the sensor's user, and the volume
    # both compose files mount there.
    dockerfile = (SERVICE_ROOT / "Dockerfile").read_text()
    assert "/var/lib/security-sensor" in dockerfile
    assert "chown -R sensor:sensor /var/lib/security-sensor" in dockerfile
    for compose in (
        SERVICE_ROOT / "docker-compose.yml",
        SERVICE_ROOT.parent / "docker-compose.yml",
    ):
        assert "sensor_data:/var/lib/security-sensor" in compose.read_text(), compose
    # On a host there is no such directory by default: not set.
    assert "data_dir" not in yaml.safe_load((SERVICE_ROOT / "config.yaml").read_text())


def test_a_copy_of_the_valid_document_is_accepted():
    # The table above changes one value at a time; this is its baseline.
    assert position_store.validate_state(copy.deepcopy(_document())) == _sources()
