"""guardian refuses to scan internal targets, through the gateway (#748).

Asset discovery and port scans connect from guardian-worker, which sits
inside the stack's networks. A team's owner or admin could point them at
the stack itself: a discovery of the worker's loopback, of the range Docker
gave the stack, or of a cloud metadata address was accepted and run. Now
the request is refused with 400 and a message that names the operator's
setting, and nothing is queued.

Each test registers an account, which is the owner of a team of its own,
and goes through the gateway.

The CI stacks are started with GUARDIAN_ALLOWED_INTERNAL_TARGETS=127.0.0.0/8
(integration-tests.yml, production-stack.yml), so that guardian's other
tests can scan a host that answers. Nothing here depends on it except the
last test, which uses an allowed discovery to show that a refused one never
reached the worker.
"""

import ipaddress
import os
import secrets
import time
import uuid

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
GUARDIAN_API = f"{GATEWAY_URL}/api/v1/guardian"
ASSETS = f"{GUARDIAN_API}/assets/assets/"
DISCOVER = f"{ASSETS}discover/"
DISCOVERY_RULES = f"{GUARDIAN_API}/assets/discovery-rules/"
TASKS = f"{GUARDIAN_API}/tasks/"

TIMEOUT = 15
TASK_DEADLINE = 90
SETTING = "GUARDIAN_ALLOWED_INTERNAL_TARGETS"

# What the worker can reach from where it runs and no caller should name:
# RFC 1918, the range Docker takes a Compose network from, link-local, cloud
# metadata, the unspecified address (the worker's own loopback, on Linux),
# their IPv6 and IPv4-mapped spellings, and a public /22 with an internal
# /24 inside it.
INTERNAL_RANGES = [
    "10.0.0.0/24",
    "172.18.0.0/24",
    "192.168.1.0/24",
    "169.254.169.254/32",
    "169.254.0.0/24",
    "0.0.0.0/32",
    "fe80::/120",
    "fd00::/118",
    "::ffff:10.0.0.0/120",
    "203.0.112.0/22",
]


def _allowed_here():
    """The ranges the stack under test was started with, as the suite was told."""
    listed = []
    for entry in os.getenv(SETTING, "").split(","):
        try:
            listed.append(ipaddress.ip_network(entry.strip()))
        except ValueError:
            continue
    return listed


def _refused_here(network):
    """Is this range one the stack's operator has not opened, even in part?"""
    network = ipaddress.ip_network(network)
    return not any(
        listed.version == network.version and listed.overlaps(network)
        for listed in _allowed_here()
    )


def _loopback_allowed():
    loopback = ipaddress.ip_network("127.0.0.0/8")
    return any(
        listed.version == 4 and loopback.subnet_of(listed) for listed in _allowed_here()
    )


@pytest.fixture(scope="module")
def owner():
    """Bearer headers of a newly registered account, the owner of its team."""
    email = f"scan-targets-{secrets.token_hex(6)}@example.com"
    password = f"Scan-Targets-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    login = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert login.status_code == 200, login.text[:200]
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _assets_at(address, headers):
    response = requests.get(
        ASSETS, params={"search": address}, headers=headers, timeout=TIMEOUT
    )
    assert response.status_code == 200, response.text[:300]
    return [a for a in response.json()["results"] if a["ip_address"] == address]


def _wait_for_task(task_id, headers):
    deadline = time.monotonic() + TASK_DEADLINE
    body = {}
    while time.monotonic() < deadline:
        response = requests.get(f"{TASKS}{task_id}/", headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200, response.text[:300]
        body = response.json()
        if body["ready"]:
            return body
        time.sleep(1)
    pytest.fail(f"task {task_id} not finished after {TASK_DEADLINE}s: {body}")


def test_the_ranges_tested_are_refused_by_this_stack():
    """A stack whose operator opened all of them would test nothing."""
    assert sum(_refused_here(network) for network in INTERNAL_RANGES) >= 5


@pytest.mark.parametrize("network", INTERNAL_RANGES)
def test_a_discovery_of_an_internal_range_is_refused_and_nothing_is_queued(
    owner, network
):
    if not _refused_here(network):
        pytest.skip(f"this stack was started with {SETTING} covering {network}")

    response = requests.post(
        DISCOVER, json={"network_range": network}, headers=owner, timeout=TIMEOUT
    )

    assert response.status_code == 400, f"{response.status_code} {response.text[:300]}"
    body = response.json()
    (message,) = body["network_range"]
    assert "internal address" in message, message
    # The caller cannot change the setting; the message says what to ask for.
    assert SETTING in message, message
    # No task was queued: there is no id to ask the status of.
    assert "task_id" not in body, body


@pytest.mark.parametrize("network", ["10.0.0.0/24", "169.254.169.254/32", "fe80::/120"])
def test_a_rule_for_an_internal_range_is_not_stored(owner, network):
    if not _refused_here(network):
        pytest.skip(f"this stack was started with {SETTING} covering {network}")
    name = f"it-scan-targets-{uuid.uuid4().hex[:12]}"

    response = requests.post(
        DISCOVERY_RULES,
        json={
            "name": name,
            "discovery_type": "network_scan",
            "target_specification": {"networks": ["8.8.8.0/30", network]},
            "schedule": "0 3 * * *",
        },
        headers=owner,
        timeout=TIMEOUT,
    )

    assert response.status_code == 400, f"{response.status_code} {response.text[:300]}"
    (message,) = response.json()["target_specification"]
    assert "internal address" in message and SETTING in message, message
    listing = requests.get(
        DISCOVERY_RULES, params={"search": name}, headers=owner, timeout=TIMEOUT
    )
    assert listing.status_code == 200, listing.text[:300]
    assert [r for r in listing.json()["results"] if r["name"] == name] == []


def test_an_asset_at_an_internal_address_is_recorded_and_not_scanned(owner):
    """An inventory lists internal hosts; guardian does not connect to them."""
    address = f"10.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}.7"
    if not _refused_here(address):
        pytest.skip(f"this stack was started with {SETTING} covering {address}")
    created = requests.post(
        ASSETS,
        json={
            "name": f"it-scan-targets-{uuid.uuid4().hex[:12]}",
            "asset_type": "server",
            "ip_address": address,
        },
        headers=owner,
        timeout=TIMEOUT,
    )
    assert created.status_code == 201, created.text[:300]
    asset_id = created.json()["id"]
    try:
        response = requests.post(
            f"{ASSETS}{asset_id}/scan/", headers=owner, timeout=TIMEOUT
        )

        assert response.status_code == 400, response.text[:300]
        body = response.json()
        assert f"{address} is an internal address" in body["error"], body
        assert SETTING in body["error"], body
        assert "task_id" not in body, body
        # Still there, as it was recorded.
        assert [a["id"] for a in _assets_at(address, owner)] == [asset_id]
    finally:
        requests.delete(f"{ASSETS}{asset_id}/", headers=owner, timeout=TIMEOUT)


def test_a_refused_discovery_never_reaches_the_worker(owner):
    """The refused range is the worker's own loopback, by another name.

    A connection to 0.0.0.0 reaches the local host on Linux, so a discovery
    of 0.0.0.0/32 that ran would find a host that is up and record it as an
    asset: on the version before this, it did. Here it is refused; then a
    discovery the stack allows is queued and awaited, so the worker has
    worked through what was queued before it; and no asset at 0.0.0.0 has
    appeared.
    """
    if not _loopback_allowed():
        message = (
            f"start the stack with {SETTING}=127.0.0.0/8, and set it for the "
            "suite too"
        )
        if os.getenv("REQUIRE_ALL_SERVICES", "") in ("1", "true", "yes"):
            pytest.fail(message, pytrace=False)
        pytest.skip(message)
    control = f"127.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}.9"
    found = []
    try:
        refused = requests.post(
            DISCOVER,
            json={"network_range": "0.0.0.0/32"},
            headers=owner,
            timeout=TIMEOUT,
        )
        assert refused.status_code == 400, refused.text[:300]

        allowed = requests.post(
            DISCOVER,
            json={"network_range": f"{control}/32"},
            headers=owner,
            timeout=TIMEOUT,
        )
        assert allowed.status_code == 200, allowed.text[:300]
        status = _wait_for_task(allowed.json()["task_id"], owner)
        assert status["state"] == "SUCCESS", status

        found = _assets_at(control, owner)
        assert found, f"the allowed discovery did not record {control}"
        assert _assets_at("0.0.0.0", owner) == []
    finally:
        for asset in found + _assets_at("0.0.0.0", owner):
            requests.delete(f"{ASSETS}{asset['id']}/", headers=owner, timeout=TIMEOUT)
