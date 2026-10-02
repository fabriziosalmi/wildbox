"""Tests for check_redis_config.py, the guard that keeps production Redis on noeviction.

docker-compose.prod.yml replaced the base file's `--maxmemory-policy
noeviction` with `allkeys-lru` (#530), so under memory pressure Redis could
evict the token blacklist, the failed-login lockout counters and the task
queues. These feed the checker rendered-service dictionaries shaped like
`docker compose config --format json` output; the workflow "Production Stack"
runs it on the real rendering.
"""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_redis_config.py"
spec = importlib.util.spec_from_file_location("check_redis_config", SCRIPT)
crc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crc)

GIB = 1024**3


def service(command, memory=str(2 * GIB)):
    svc = {"command": command}
    if memory is not None:
        svc["deploy"] = {"resources": {"limits": {"memory": memory}}}
    return svc


GOOD = [
    "redis-server",
    "--appendonly",
    "yes",
    "--maxmemory",
    "1gb",
    "--maxmemory-policy",
    "noeviction",
    "--requirepass",
    "x",
]


def test_production_settings_pass():
    assert crc.check_service(service(GOOD)) == []


def test_command_as_string_passes():
    assert crc.check_service(service(" ".join(GOOD))) == []


@pytest.mark.parametrize(
    "policy", ["allkeys-lru", "volatile-lru", "allkeys-lfu", "volatile-ttl"]
)
def test_any_eviction_policy_fails(policy):
    cmd = [policy if a == "noeviction" else a for a in GOOD]
    failures = crc.check_service(service(cmd))
    assert len(failures) == 1 and "maxmemory-policy" in failures[0]


def test_policy_overridden_later_on_the_command_line_fails():
    failures = crc.check_service(service(GOOD + ["--maxmemory-policy", "allkeys-lru"]))
    assert any("maxmemory-policy" in f for f in failures)


def test_missing_policy_fails():
    # redis-server's built-in default is noeviction, but a command that does
    # not say so is one edit away from not being it.
    cmd = GOOD[:5] + GOOD[7:]
    assert any("maxmemory-policy" in f for f in crc.check_service(service(cmd)))


def test_the_overlay_that_shipped_fails():
    # docker-compose.prod.yml before #530: 512mb, allkeys-lru, 512M limit.
    old = [
        "redis-server",
        "--maxmemory",
        "512mb",
        "--maxmemory-policy",
        "allkeys-lru",
        "--appendonly",
        "yes",
        "--requirepass",
        "x",
    ]
    failures = crc.check_service(service(old, memory=str(512 * 1024**2)))
    assert any("maxmemory-policy" in f for f in failures)
    assert any("memory limit" in f for f in failures)


def test_no_command_fails():
    assert crc.check_service({"deploy": {}}) != []


def test_missing_maxmemory_fails():
    cmd = GOOD[:3] + GOOD[5:]
    assert any("--maxmemory missing" in f for f in crc.check_service(service(cmd)))


def test_unlimited_maxmemory_fails():
    cmd = [("0" if a == "1gb" else a) for a in GOOD]
    assert any("unlimited" in f for f in crc.check_service(service(cmd)))


def test_missing_appendonly_fails():
    cmd = GOOD[:1] + GOOD[3:]
    assert any("appendonly" in f for f in crc.check_service(service(cmd)))


@pytest.mark.parametrize("memory", [str(GIB), str(int(1.5 * GIB)), str(2 * GIB - 1)])
def test_limit_below_twice_maxmemory_fails(memory):
    failures = crc.check_service(service(GOOD, memory=memory))
    assert len(failures) == 1 and "memory limit" in failures[0]


def test_missing_limit_fails():
    assert any(
        "limits.memory" in f for f in crc.check_service(service(GOOD, memory=None))
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1gb", GIB),
        ("1g", 10**9),
        ("512mb", 512 * 1024**2),
        ("100", 100),
        ("2GB", 2 * GIB),
    ],
)
def test_redis_bytes(value, expected):
    assert crc.redis_bytes(value) == expected


@pytest.mark.parametrize("value", ["", "1tb", "lots", "-1gb"])
def test_redis_bytes_rejects(value):
    with pytest.raises(ValueError):
        crc.redis_bytes(value)
