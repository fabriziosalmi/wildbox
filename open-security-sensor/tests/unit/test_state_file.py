"""The file the sensor keeps its own state in, whatever the state is (#745).

The log positions and the file monitor's baseline are written and read by
the same code: atomically, and without trust. ``test_position_store.py``
exercises it through the position store; here is what two stores in one
directory add, and what only the larger of them reaches.
"""

import os
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.utils import state_file  # noqa: E402
from sensor.utils.state_file import Invalid, StateFile  # noqa: E402


def _file(directory, name="fim-baseline.json", max_bytes=1000):
    return StateFile(str(directory), name, max_bytes, "a baseline file")


def test_what_is_written_is_what_is_read(tmp_path):
    kept = _file(tmp_path)

    kept.write(b'{"a": 1}')
    kept.write(b'{"a": 2}')

    assert kept.read() == b'{"a": 2}'
    assert os.listdir(tmp_path) == ["fim-baseline.json"]
    assert (tmp_path / "fim-baseline.json").stat().st_mode & 0o777 == 0o600


def test_without_a_file_reading_says_so(tmp_path):
    with pytest.raises(FileNotFoundError):
        _file(tmp_path).read()


def test_more_than_the_file_may_hold_is_not_written(tmp_path):
    kept = _file(tmp_path, max_bytes=10)
    kept.write(b"0123456789")

    with pytest.raises(OSError) as refused:
        kept.write(b"0123456789a")

    assert str(refused.value) == ("it takes 11 bytes, more than the file may hold (10)")
    # The file is the one before, and nothing is left beside it.
    assert kept.read() == b"0123456789"
    assert os.listdir(tmp_path) == ["fim-baseline.json"]


def test_a_file_that_grew_past_the_limit_is_refused_by_its_size(tmp_path):
    kept = _file(tmp_path, max_bytes=10)
    (tmp_path / "fim-baseline.json").write_bytes(b"x" * 11)

    with pytest.raises(Invalid) as refused:
        kept.read()

    assert str(refused.value) == (
        "its 11 bytes are more than a baseline file holds (10)"
    )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO")
def test_something_that_is_not_a_regular_file_is_refused_as_such(tmp_path):
    # Opening does not wait for a writer, and nothing is read from it.
    os.mkfifo(tmp_path / "fim-baseline.json")

    with pytest.raises(Invalid) as refused:
        _file(tmp_path).read()

    assert str(refused.value) == "it is not a regular file"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs a link")
def test_a_link_is_not_followed(tmp_path):
    (tmp_path / "elsewhere").write_bytes(b"{}")
    os.symlink(tmp_path / "elsewhere", tmp_path / "fim-baseline.json")

    with pytest.raises(OSError):
        _file(tmp_path).read()


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="needs file owners")
def test_a_file_of_another_user_is_refused(tmp_path, monkeypatch):
    kept = _file(tmp_path)
    kept.write(b"{}")
    monkeypatch.setattr(state_file.os, "geteuid", lambda: os.getuid() + 1)

    with pytest.raises(Invalid, match="not to the sensor's user"):
        kept.read()


def test_a_save_that_fails_leaves_the_file_and_no_temporary_one(tmp_path, monkeypatch):
    kept = _file(tmp_path)
    kept.write(b"before")

    def no_rename(source, target):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(state_file.os, "replace", no_rename)
    with pytest.raises(OSError):
        kept.write(b"after")

    assert kept.read() == b"before"
    assert os.listdir(tmp_path) == ["fim-baseline.json"]


def test_each_file_removes_its_own_leftovers_only(tmp_path):
    # Two stores, one directory: what a crash left of one save is not the
    # other store's to remove, and neither is anything else.
    mine = tmp_path / ".fim-baseline.abc123.tmp"
    theirs = tmp_path / ".log-positions.def456.tmp"
    other = tmp_path / ".something-else.tmp"
    plain = tmp_path / "fim-baseline.json.bak"
    for path in (mine, theirs, other, plain):
        path.write_text("left")

    _file(tmp_path).remove_leftovers()

    assert sorted(os.listdir(tmp_path)) == sorted([theirs.name, other.name, plain.name])

    _file(tmp_path, name="log-positions.json").remove_leftovers()

    assert sorted(os.listdir(tmp_path)) == sorted([other.name, plain.name])
