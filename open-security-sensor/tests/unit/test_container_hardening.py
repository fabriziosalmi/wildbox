"""The sensor's container has no capability, in every compose file that runs it (#725).

The sensor's README and DOCKER.md say the container runs as a non-root user
with ``no-new-privileges`` and ``cap_drop: ALL``. Only the standalone compose
file dropped the capabilities: the root ``docker-compose.yml``, the one the
default stack is started from, did not.

What the collectors need was checked in the built image as uid 999, with and
without the capabilities (the pull request has the output): nothing differs.
That check needs Docker and is not repeated here; this pins the files.
"""

import sys
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
sys.path.insert(0, str(SERVICE_ROOT))

COMPOSE_FILES = [
    REPO_ROOT / "docker-compose.yml",
    SERVICE_ROOT / "docker-compose.yml",
    SERVICE_ROOT / "docker-compose.dev.yml",
]
# Overlays of the root file: they must not give back what it takes away.
OVERLAYS = [
    REPO_ROOT / "docker-compose.prod.yml",
    REPO_ROOT / "docker-compose.dev.yml",
    SERVICE_ROOT / "docker-compose.scale.yml",
]


class _Compose(yaml.SafeLoader):
    """Compose's own tags (!override, !reset) around plain YAML."""


def _tagged(loader, suffix, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


_Compose.add_multi_constructor("!", _tagged)


def _sensor(path):
    if not path.exists():
        pytest.skip(f"{path.name} is not in this checkout")
    services = yaml.load(path.read_text(), Loader=_Compose).get("services") or {}
    # The development file calls it sensor-dev.
    return services.get("sensor") or services.get("sensor-dev")


@pytest.mark.parametrize(
    "path", COMPOSE_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_the_sensor_drops_every_capability_and_cannot_gain_one(path):
    sensor = _sensor(path)

    assert sensor is not None, f"{path} has no sensor service"
    # main: the root docker-compose.yml had no cap_drop at all.
    assert sensor.get("cap_drop") == ["ALL"]
    assert "no-new-privileges:true" in sensor.get("security_opt", [])
    _nothing_given_back(sensor)


@pytest.mark.parametrize("path", OVERLAYS, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_no_overlay_gives_the_sensor_a_privilege_back(path):
    sensor = _sensor(path)

    if sensor is None:
        return  # the overlay does not touch the sensor
    assert "cap_drop" not in sensor and "security_opt" not in sensor
    _nothing_given_back(sensor)


def _nothing_given_back(sensor):
    assert "cap_add" not in sensor
    assert sensor.get("privileged") in (None, False)
    for namespace in ("pid", "network_mode", "ipc", "userns_mode"):
        assert sensor.get(namespace) != "host", namespace
    # The image's user, uid 999; not root by an override.
    assert str(sensor.get("user", "sensor")) not in ("0", "root", "0:0", "root:root")
    assert not any(
        isinstance(volume, str) and "docker.sock" in volume
        for volume in sensor.get("volumes", [])
    )


def test_the_image_runs_as_the_sensor_user():
    dockerfile = (SERVICE_ROOT / "Dockerfile").read_text()
    instructions = [
        line.split()
        for line in dockerfile.splitlines()
        if line.startswith(("USER ", "CMD ", "ENTRYPOINT "))
    ]

    users = [words[1] for words in instructions if words[0] == "USER"]
    assert users == ["sensor"]
    # And the process is started after the switch, not before.
    assert [words[0] for words in instructions] == ["USER", "CMD"]


def test_the_documents_claim_what_the_files_do():
    readme = " ".join((SERVICE_ROOT / "README.md").read_text().split())
    docker_md = " ".join((SERVICE_ROOT / "DOCKER.md").read_text().split())

    assert "all capabilities dropped (`cap_drop: ALL`)" in readme
    assert "`no-new-privileges:true` and `cap_drop: ALL`" in docker_md
