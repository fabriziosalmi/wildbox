"""The default temporary directory must follow TMPDIR on Unix-like hosts.

It used to be the literal "/tmp", so an operator who pointed TMPDIR at a
private directory still got the shared, world-writable one.
"""

import sys
import tempfile
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.utils import platform as sensor_platform  # noqa: E402


@pytest.fixture
def private_tmpdir(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    # tempfile caches the directory it picked; forget it for this test only.
    monkeypatch.setattr(tempfile, "tempdir", None)
    monkeypatch.setattr(sensor_platform, "is_windows", lambda: False)
    return tmp_path


def test_unix_temp_dir_follows_tmpdir(private_tmpdir):
    paths = sensor_platform.get_default_paths()

    assert Path(paths["temp_dir"]).resolve() == private_tmpdir.resolve()
