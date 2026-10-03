"""Network tools refuse internal targets, through the gateway (#614).

The tools that scan a host, an address or a range used to accept the
platform's own network: any authenticated user could point port_scanner at
wildbox-redis. Now the target policy refuses internal targets before the
tool runs, on the synchronous endpoint and in the Celery worker, unless the
operator lists them in TOOLS_ALLOWED_INTERNAL_TARGETS.

The integration workflow starts the stack with
TOOLS_ALLOWED_INTERNAL_TARGETS=198.18.0.0/15, the benchmarking range
(RFC 2544), which the policy refuses by default and nothing routes. No test
scans anything reachable: refused requests stop before the tool runs, and
the allowed scan probes one port of an address that does not answer.

Accounts are registered at identity directly, as test_tools_async_tasks.py
does; every tool request goes through the gateway.
"""

import ipaddress
import os
import secrets
import time

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001")
TIMEOUT = 15
FINISH_WITHIN = 120
UNFINISHED = {"pending", "running", "retrying"}
POLICY = "network target policy"

LAB_RANGE = ipaddress.ip_network("198.18.0.0/15")
LAB_TARGET = "198.18.0.1"


def lab_range_allowed():
    """Whether the stack under test was started with the lab range allowed."""
    raw = os.getenv("TOOLS_ALLOWED_INTERNAL_TARGETS", "")
    for entry in raw.split(","):
        try:
            if ipaddress.ip_network(entry.strip()) == LAB_RANGE:
                return True
        except ValueError:
            continue
    return False


@pytest.fixture(scope="module")
def headers():
    email = f"target-policy-{secrets.token_hex(6)}@example.com"
    password = f"Target-Policy-{secrets.token_hex(8)}!"
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


def run_tool(headers, tool, payload):
    return requests.post(
        f"{GATEWAY_URL}/api/v1/tools/{tool}",
        json=payload,
        headers=headers,
        timeout=TIMEOUT,
    )


def run_async(headers, tool, payload):
    submitted = requests.post(
        f"{GATEWAY_URL}/api/v1/tools/{tool}/async",
        json=payload,
        headers=headers,
        timeout=TIMEOUT,
    )
    assert submitted.status_code == 202, submitted.text[:300]
    task_id = submitted.json()["task_id"]
    deadline = time.monotonic() + FINISH_WITHIN
    while True:
        response = requests.get(
            f"{GATEWAY_URL}/api/v1/tasks/{task_id}", headers=headers, timeout=TIMEOUT
        )
        assert response.status_code == 200, response.text[:300]
        body = response.json()
        if body["status"] not in UNFINISHED:
            return body
        assert time.monotonic() < deadline, f"task still {body['status']}: {body}"
        time.sleep(1)


@pytest.mark.parametrize(
    "tool,payload",
    [
        ("port_scanner", {"target": "127.0.0.1", "ports": [6379]}),
        ("port_scanner", {"target": "wildbox-redis", "ports": [6379]}),
        ("network_port_scanner", {"target": "169.254.169.254", "ports": "80"}),
        ("ssl_analyzer", {"target": "postgres", "port": 5432}),
        ("network_scanner", {"network": "172.16.0.0/22"}),
    ],
)
def test_an_internal_target_is_refused_before_the_tool_runs(headers, tool, payload):
    response = run_tool(headers, tool, payload)

    assert (
        response.status_code == 400
    ), f"HTTP {response.status_code}: {response.text[:300]}"
    assert POLICY in response.text, response.text[:300]


def test_an_internal_target_is_refused_in_the_worker(headers):
    body = run_async(
        headers, "port_scanner", {"target": "wildbox-redis", "ports": [6379]}
    )

    assert body["status"] == "failed", body
    assert POLICY in (body.get("error") or ""), body


def test_an_address_outside_the_allowlist_stays_refused(headers):
    if not lab_range_allowed():
        pytest.skip("the stack was not started with 198.18.0.0/15 allowed")
    response = run_tool(headers, "port_scanner", {"target": "10.0.0.1", "ports": [9]})

    assert response.status_code == 400, response.text[:300]
    assert POLICY in response.text, response.text[:300]


def test_an_allow_listed_lab_address_is_scanned(headers):
    """The worker runs the scan: one port, one second, nothing answers.

    The asynchronous path, because the synchronous one gives the whole run
    the same time limit as one port, and a port that does not answer would
    time the request out rather than show what the policy decided.
    """
    if not lab_range_allowed():
        pytest.skip("the stack was not started with 198.18.0.0/15 allowed")
    body = run_async(
        headers, "port_scanner", {"target": LAB_TARGET, "ports": [9], "timeout": 1}
    )

    assert body["status"] == "completed", body
    assert body["result"]["target"] == LAB_TARGET, body
