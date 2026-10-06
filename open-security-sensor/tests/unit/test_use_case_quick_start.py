"""The web-attack-detection quick start runs on a current Docker (#725).

``quick-start.sh`` looked for the ``docker-compose`` v1 binary and stopped
when it was missing. Docker has not shipped it for years: Compose is the
``docker compose`` plugin, which is what every other script here calls.

The script is run for real up to its Compose check, with a ``docker`` that
answers like a Docker with the plugin and without the v1 binary.
"""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
USE_CASE = REPO_ROOT / "use-cases" / "web-attack-detection"
QUICK_START = USE_CASE / "quick-start.sh"

pytestmark = pytest.mark.skipif(
    not QUICK_START.exists(), reason="not a repository checkout: no use case here"
)

# The v1 binary's name used as a command: not a file name such as
# docker-compose.yml or docker-compose.override.yml.
V1_COMMAND = re.compile(r"docker-compose(?![.\w-])")


def _fake_docker(directory, compose_plugin):
    """A ``docker`` that knows ``info`` and, with the plugin, ``compose``."""
    script = directory / "docker"
    # With the plugin: a stack that is up, so that the script does not start
    # one and wait for it.
    compose = (
        '[ "$2" = ps ] && echo "open-security-gateway Up"; exit 0'
        if compose_plugin
        else "echo unknown command >&2; exit 1"
    )
    script.write_text(
        "#!/bin/sh\n"
        'echo "$@" >> "$FAKE_DOCKER_CALLS"\n'
        'case "$1" in\n'
        "  info) exit 0 ;;\n"
        f"  compose) {compose} ;;\n"
        "esac\n"
        "exit 1\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)


SYSTEM_PATH = ["/usr/bin", "/bin"]


def _run(tmp_path, compose_plugin, v1_binary=False):
    """Run the quick start from a copy of the use case, with a PATH that has
    the fake docker first and then the system's tools. ``v1_binary`` puts a
    ``docker-compose`` there too, which records that it was called."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _fake_docker(bin_dir, compose_plugin)
    calls = tmp_path / "calls"
    calls.write_text("")
    if v1_binary:
        old_binary = bin_dir / "docker-compose"
        old_binary.write_text(
            '#!/bin/sh\necho "docker-compose $@" >> "$FAKE_DOCKER_CALLS"\nexit 0\n'
        )
        old_binary.chmod(old_binary.stat().st_mode | stat.S_IXUSR)
    # The script's own directory, so that it gets past its first check; the
    # stack it would start next is the fake docker's business.
    work = tmp_path / "wildbox" / "use-cases" / "web-attack-detection"
    shutil.copytree(USE_CASE, work)
    environment = {
        "PATH": os.pathsep.join([str(bin_dir)] + SYSTEM_PATH),
        "FAKE_DOCKER_CALLS": str(calls),
        "HOME": str(tmp_path),
        # Where the script puts its sample logs, instead of /tmp.
        "WILDBOX_TEST_DIR": str(tmp_path / "wildbox-test"),
    }
    result = subprocess.run(
        ["bash", str(work / "quick-start.sh")],
        cwd=work,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result, calls.read_text().splitlines()


def _no_v1_binary_here():
    """Is the machine like a current Docker installation: no docker-compose
    among the system's tools?"""
    return not any((Path(d) / "docker-compose").exists() for d in SYSTEM_PATH)


def test_the_script_never_calls_the_v1_binary():
    text = QUICK_START.read_text()

    assert V1_COMMAND.findall(text) == []
    assert "docker compose version" in text
    assert subprocess.run(["bash", "-n", str(QUICK_START)]).returncode == 0


def test_with_the_compose_plugin_and_no_v1_binary_the_check_passes(tmp_path):
    if not _no_v1_binary_here():
        pytest.skip("this machine has a docker-compose binary among its system tools")
    result, calls = _run(tmp_path, compose_plugin=True)

    # main: "Error: docker-compose is not installed", exit 1.
    assert "docker-compose is not installed" not in result.stdout
    assert "Docker Compose is available" in result.stdout
    assert "compose version" in calls
    # It went on to look at the stack, with the plugin, and stopped where
    # it needs a real gateway.
    assert "compose ps" in calls
    assert "Wildbox services are running" in result.stdout
    assert (tmp_path / "wildbox-test" / "logs" / "access.log").exists()


def test_a_v1_binary_that_is_there_is_not_what_the_script_calls(tmp_path):
    result, calls = _run(tmp_path, compose_plugin=True, v1_binary=True)

    assert "Docker Compose is available" in result.stdout
    assert "compose ps" in calls
    # main: "docker-compose ps".
    assert [call for call in calls if call.startswith("docker-compose")] == []


def test_without_compose_it_stops_and_says_what_is_missing(tmp_path):
    # Even with the v1 binary there: it is not what the script needs.
    result, calls = _run(tmp_path, compose_plugin=False, v1_binary=True)

    assert result.returncode == 1
    assert "Docker Compose is not available" in result.stdout
    assert calls == ["info", "compose version"]


@pytest.mark.parametrize("document", ["README.md", "docs/testing-guide.md"])
def test_the_use_cases_documents_show_the_same_command(document):
    text = (USE_CASE / document).read_text()

    assert V1_COMMAND.findall(text) == []
    assert "docker compose " in text
