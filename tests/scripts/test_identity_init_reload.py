"""identity's start script passes --reload in development only (#664).

open-security-identity/scripts/init.sh is the image's CMD, and it started
uvicorn with --reload unconditionally: production ran a file-watching
reloader that restarts the server in a second process. The script is run
here as the image runs it, with python, alembic and uvicorn replaced by
stubs on PATH; the uvicorn stub records the arguments it was started with.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INIT = ROOT / "open-security-identity" / "scripts" / "init.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def stub(directory, name, body):
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


def start(tmp_path, environment):
    """Run init.sh; return the argument list uvicorn was started with."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "uvicorn.args"
    # The database check and the superuser step are `python -c ...`.
    stub(bin_dir, "python", "exit 0")
    stub(bin_dir, "alembic", "exit 0")
    stub(bin_dir, "uvicorn", f'printf "%s\\n" "$@" > "{record}"')

    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("ENVIRONMENT", "PATH")
    }
    env["PATH"] = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
    if environment is not None:
        env["ENVIRONMENT"] = environment
    result = subprocess.run(
        ["bash", str(INIT)],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return record.read_text().split()


def test_development_reloads(tmp_path):
    args = start(tmp_path, "development")
    assert args[0] == "app.main:app"
    assert "--reload" in args


@pytest.mark.parametrize("environment", ["production", "staging", "", None])
def test_any_other_environment_does_not_reload(tmp_path, environment):
    args = start(tmp_path, environment)
    assert "--reload" not in args
    # Everything else as before: the same app, address and port, and one
    # process (no --workers).
    assert args == ["app.main:app", "--host", "0.0.0.0", "--port", "8001"]
