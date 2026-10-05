"""Every service of the production configuration rotates its container log.

Docker's default json-file driver keeps everything a container prints in one
file and never rotates it. docker-compose.prod.yml set `max-size` and
`max-file` for eleven services and left ten without: Prometheus and
Alertmanager, added with the monitoring profile (#658), and before them the
tools worker and Flower, the data API and its scheduler, CSPM, the sensor,
n8n and the backup loop (#726). On a host that stays up, those files grow
until the disk is full.
"""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_container_hygiene.py"
spec = importlib.util.spec_from_file_location("check_container_hygiene", SCRIPT)
cch = importlib.util.module_from_spec(spec)
# dataclasses resolves string annotations through sys.modules.
sys.modules[spec.name] = cch
spec.loader.exec_module(cch)

SIZE = re.compile(r"^[1-9]\d*[kmg]$")


def services(name: str) -> dict:
    # The checker's loader reads Compose's own tags (!override, !reset).
    document = cch.load_compose((REPO / name).read_text(encoding="utf-8"))
    assert document is not None, name
    return document["services"]


BASE = services("docker-compose.yml")
OVERLAY = services("docker-compose.prod.yml")


def rotation_problem(logging) -> str:
    """Why a `logging` block does not bound the log, or '' when it does."""
    if not isinstance(logging, dict):
        return "has no logging block"
    if logging.get("driver", "json-file") not in ("json-file", "local"):
        return ""  # shipped elsewhere (syslog, journald): not a file Docker grows
    options = logging.get("options") or {}
    if not SIZE.match(str(options.get("max-size", ""))):
        return f"has no max-size (got {options.get('max-size')!r})"
    files = str(options.get("max-file", ""))
    if not files.isdigit() or int(files) < 1:
        return f"has no max-file (got {options.get('max-file')!r})"
    return ""


def test_the_base_file_defines_the_services_this_test_reads():
    assert len(BASE) >= 20, sorted(BASE)
    for name in ("prometheus", "alertmanager", "tools-worker", "backup"):
        assert name in BASE


@pytest.mark.parametrize("name", sorted(BASE))
def test_every_service_rotates_its_log_in_production(name):
    logging = (OVERLAY.get(name) or {}).get("logging", BASE[name].get("logging"))
    assert rotation_problem(logging) == "", f"{name} {rotation_problem(logging)}"


def test_the_overlay_names_no_service_the_base_file_lacks():
    assert sorted(set(OVERLAY) - set(BASE)) == []


@pytest.mark.parametrize(
    "logging, says",
    [
        (None, "no logging block"),
        ({"driver": "json-file"}, "no max-size"),
        ({"driver": "json-file", "options": {"max-file": "3"}}, "no max-size"),
        ({"driver": "json-file", "options": {"max-size": "10m"}}, "no max-file"),
        ({"options": {"max-size": "0", "max-file": "3"}}, "no max-size"),
        ({"options": {"max-size": "10m", "max-file": "0"}}, "no max-file"),
        ({"driver": "local", "options": {"max-file": "3"}}, "no max-size"),
    ],
)
def test_a_log_without_a_bound_is_a_problem(logging, says):
    assert says in rotation_problem(logging)


@pytest.mark.parametrize(
    "logging",
    [
        {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
        {"options": {"max-size": "500k", "max-file": 5}},
        {"driver": "syslog", "options": {"syslog-address": "udp://logs:514"}},
    ],
)
def test_a_bounded_or_shipped_log_passes(logging):
    assert rotation_problem(logging) == ""
