"""
The gateway's revocation endpoint answers what identity parses (#571).

Logout fails closed: identity answers success only once the gateway has
confirmed, in a JSON body, how many jtis it revoked. The gateway's answer used
to end in a stray "nil" (ngx.say printed json_encode's second return value),
so every logout on a real stack answered 503, while the gateway harness, which
looked at the status only, passed.

The endpoint lives on the gateway's internal listener (port 8081), which is
not published, so the request is made from inside the identity container, by
the same path and with the same secret identity uses. The secret is read there
and never leaves the container.
"""

import json
import shutil
import subprocess
import uuid

import pytest

IDENTITY_CONTAINER = "open-security-identity"

# Runs in the identity container. Prints the status and the raw body only.
PROBE = """
import json, os, sys
import httpx
from app.gateway_cache import _DEFAULT_URL
response = httpx.post(
    _DEFAULT_URL,
    json={"jtis": [sys.argv[1]], "ttl": 60},
    headers={"X-Gateway-Secret": os.environ["GATEWAY_INTERNAL_SECRET"]},
    timeout=10,
)
print(json.dumps({"status": response.status_code, "body": response.text}))
"""

# Runs in the identity container: the client logout itself relies on.
CLIENT = """
import asyncio, sys
from app.gateway_cache import revoke_jtis_at_gateway
asyncio.run(revoke_jtis_at_gateway([sys.argv[1]], ttl_seconds=60))
print("confirmed")
"""


def _in_identity(script: str, *args: str) -> subprocess.CompletedProcess:
    if shutil.which("docker") is None:
        pytest.skip("docker is not available to reach the internal listener")
    result = subprocess.run(
        ["docker", "exec", IDENTITY_CONTAINER, "python", "-c", script, *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0 and "No such container" in result.stderr:
        pytest.skip(f"{IDENTITY_CONTAINER} is not running")
    return result


def test_the_purge_answer_is_strict_json_counting_the_jtis():
    result = _in_identity(PROBE, f"contract-{uuid.uuid4().hex}")
    assert result.returncode == 0, result.stderr[-500:]
    answer = json.loads(result.stdout)
    assert answer["status"] == 200, answer["body"][:200]
    # json.loads is as strict as httpx's response.json(): trailing bytes fail.
    body = json.loads(answer["body"])
    assert body["revoked"] == 1, body
    assert body["scope"] == "jtis", body


def test_identity_s_client_gets_the_revocation_confirmed():
    result = _in_identity(CLIENT, f"contract-{uuid.uuid4().hex}")
    assert result.returncode == 0 and "confirmed" in result.stdout, result.stderr[-500:]
