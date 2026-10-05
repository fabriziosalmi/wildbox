"""The agent's tools reach the data service and Guardian as the caller (#652).

The threat-intelligence and vulnerability tools called routes that do not
exist, at localhost inside the agents container, so the model never got an
answer from either service. They now call ``GET /api/v1/indicators/search``
on the data service and ``GET /api/v1/vulnerabilities/`` on Guardian, at the
addresses docker-compose.yml gives the container, with the identity of the
user who submitted the analysis.

A tool is called by the model, and this suite has no model key. So the tests
run the tools themselves inside the running agents container, with its own
configuration and network, for a caller the test registered: the same code
path the worker takes once the model has chosen a tool. What they check
through the gateway is that the tool, acting for a user, sees what that user
sees there:

- team A's owner records a vulnerability in Guardian through the gateway;
  the tool finds it as A and not as B, the owner of another team;
- the indicator search answers, as the caller, the same total the gateway
  gives that caller; with direct database access (DATA_DB_DSN) a team's own
  indicator is found by the tool as that team and not as the other.

The model is given these two tools only when the operator names them in
AGENT_TEAM_DATA_TOOLS; by default it has neither. The CI stack is started
with both (integration-tests.yml), and the same variable is passed to this
suite: with it set, a tool missing from the container fails the test; on a
stack started without it the tests are skipped, saying how to enable them.

Each request is sent once; nothing is polled.
"""

import json
import os
import secrets
import shutil
import subprocess
import uuid
from datetime import datetime, timezone

import pytest
import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
AGENTS_CONTAINER = os.getenv("AGENTS_CONTAINER", "open-security-agents")
TIMEOUT = 15

GUARDIAN_API = f"{GATEWAY_URL}/api/v1/guardian"
ASSETS = f"{GUARDIAN_API}/assets/assets/"
VULNERABILITIES = f"{GUARDIAN_API}/vulnerabilities/"
INDICATOR_SEARCH = f"{GATEWAY_URL}/api/v1/data/indicators/search"

# The team-data tools the stack under test was started with: what the CI
# workflow passes to `docker compose up` and to this suite. They are off by
# default, so a stack started without the variable does not have them.
EXPECTED_TEAM_DATA_TOOLS = {
    name.strip()
    for name in os.getenv("AGENT_TEAM_DATA_TOOLS", "").split(",")
    if name.strip()
}

# Runs in the agents container: one of the tools the service gives its model
# there, as the caller given on stdin. The tool is taken from the list the
# agent itself builds, with the container's own settings, so a tool the
# operator did not enable is not run here either.
RUN_TOOL = """
import asyncio, json, sys
from app.config import settings
from app.tools.langchain_tools import enabled_tools
from app.tools.wildbox_client import caller_identity

caller = json.loads(sys.stdin.read())
given = {tool.name: tool for tool in enabled_tools(settings.team_data_tool_names())}
if sys.argv[1] not in given:
    print(json.dumps({"not_given_to_the_model": sys.argv[1], "given": sorted(given)}))
    sys.exit(0)
with caller_identity(caller):
    print(asyncio.run(given[sys.argv[1]].ainvoke(json.loads(sys.argv[2]))))
"""


def in_agents(script, *args, stdin=""):
    if shutil.which("docker") is None:
        pytest.skip("docker is not available to run the tool in its container")
    result = subprocess.run(
        ["docker", "exec", "-i", AGENTS_CONTAINER, "python", "-c", script, *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if result.returncode != 0 and "No such container" in result.stderr:
        pytest.skip(f"{AGENTS_CONTAINER} is not running")
    return result


def run_tool(caller, tool, **args):
    """What ``tool`` returns to the model when it runs for ``caller``."""
    result = in_agents(RUN_TOOL, tool, json.dumps(args), stdin=json.dumps(caller))
    assert result.returncode == 0, result.stderr[-800:]
    # The tool's JSON is the last thing printed; log lines may precede it.
    output = json.loads(result.stdout[result.stdout.index("{") :])
    if "not_given_to_the_model" in output:
        # A stack that was started with the tool must have it: a skip here
        # would hide the tool silently missing from the CI stack.
        assert tool not in EXPECTED_TEAM_DATA_TOOLS, (
            f"the stack was started with AGENT_TEAM_DATA_TOOLS naming {tool}, "
            f"but the agents container gives its model only {output['given']}"
        )
        pytest.skip(
            f"{tool} is not given to the model in this stack: start it with "
            f"AGENT_TEAM_DATA_TOOLS={tool} (and set the same for this suite)"
        )
    return output


def new_owner():
    """A newly registered account, the owner of its own team.

    Returns its bearer headers and the identity the gateway forwards for it.
    """
    email = f"agents-tools-{secrets.token_hex(6)}@example.com"
    password = f"Agents-Tools-{secrets.token_hex(8)}!"
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
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    # The user's own record: its first membership is the team the gateway
    # forwards for a session (identity's /internal/authorize picks the same).
    profile = requests.get(
        f"{GATEWAY_URL}/api/v1/identity/admin/me/activity",
        headers=headers,
        timeout=TIMEOUT,
    )
    assert profile.status_code == 200, profile.text[:300]
    membership = profile.json()["team_memberships"][0]
    caller = {
        "user_id": profile.json()["user_id"],
        "team_id": membership["team_id"],
        "role": membership["role"],
    }
    assert caller["user_id"] == registered.json()["id"]
    return headers, caller


@pytest.fixture
def owners():
    return new_owner(), new_owner()


@pytest.fixture
def team_a_vulnerability(owners):
    """A vulnerability team A records through the gateway; removed afterwards."""
    (a, _), _ = owners
    marker = f"it-agents-{uuid.uuid4().hex[:12]}"
    asset = requests.post(
        ASSETS,
        json={"name": marker, "asset_type": "server", "hostname": "it-agents.invalid"},
        headers=a,
        timeout=TIMEOUT,
    )
    assert asset.status_code == 201, asset.text[:300]
    asset_id = asset.json()["id"]
    created = requests.post(
        VULNERABILITIES,
        json={
            "title": f"{marker} OpenSSH regreSSHion",
            "description": "tool identity probe",
            "asset": asset_id,
            "severity": "high",
            # cve_id and port complete the unique (asset, cve_id, port) key.
            "cve_id": "CVE-2024-6387",
            "port": 22,
        },
        headers=a,
        timeout=TIMEOUT,
    )
    assert created.status_code == 201, created.text[:300]
    yield marker
    listed = requests.get(
        VULNERABILITIES, params={"search": marker}, headers=a, timeout=TIMEOUT
    )
    for row in listed.json().get("results", []):
        requests.delete(f"{VULNERABILITIES}{row['id']}/", headers=a, timeout=TIMEOUT)
    requests.delete(f"{ASSETS}{asset_id}/", headers=a, timeout=TIMEOUT)


def test_the_vulnerability_tool_finds_what_the_caller_has_in_guardian(
    owners, team_a_vulnerability
):
    (a_headers, a), (b_headers, b) = owners
    marker = team_a_vulnerability

    as_a = run_tool(a, "vulnerability_search_tool", query=marker)
    as_b = run_tool(b, "vulnerability_search_tool", query=marker)

    assert as_a["success"] is True, as_a
    assert as_a["total"] == 1
    [found] = as_a["vulnerabilities"]
    assert found["title"] == f"{marker} OpenSSH regreSSHion"
    assert found["cve_id"] == "CVE-2024-6387"
    assert found["asset_name"] == marker
    # Another team's owner, through the same tool: Guardian answers, with
    # nothing of team A's.
    assert as_b["success"] is True, as_b
    assert as_b["total"] == 0 and as_b["vulnerabilities"] == []

    # Which is what each of them sees through the gateway.
    for headers, seen in ((a_headers, as_a), (b_headers, as_b)):
        listed = requests.get(
            VULNERABILITIES, params={"search": marker}, headers=headers, timeout=TIMEOUT
        )
        assert listed.status_code == 200, listed.text[:300]
        assert listed.json()["count"] == seen["total"]


def test_the_threat_intel_tool_answers_what_the_gateway_answers_the_caller(owners):
    (a_headers, a), _ = owners
    query = f"it-agents-{uuid.uuid4().hex[:12]}.invalid"

    output = run_tool(a, "threat_intel_query_tool", ioc_value=query, ioc_type="domain")

    assert output["success"] is True, output
    assert output["indicator_type"] == "domain"
    through_gateway = requests.get(
        INDICATOR_SEARCH,
        params={"q": query, "indicator_type": "domain"},
        headers=a_headers,
        timeout=TIMEOUT,
    )
    assert through_gateway.status_code == 200, through_gateway.text[:300]
    assert output["total"] == through_gateway.json()["total"] == 0
    assert output["indicators"] == []


def test_the_threat_intel_tool_finds_a_teams_indicator_only_as_that_team(owners):
    dsn = os.environ.get("DATA_DB_DSN", "")
    if not dsn:
        pytest.skip("DATA_DB_DSN not set: no way to store a team's indicator")
    psycopg2 = pytest.importorskip("psycopg2")
    from psycopg2.extras import Json

    (_, a), (_, b) = owners
    value = f"it-agents-{uuid.uuid4().hex[:12]}.invalid"
    source_id, indicator_id = uuid.uuid4(), uuid.uuid4()
    now = datetime.now(timezone.utc)
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sources (id, team_id, name, source_type, enabled) VALUES (%s, %s, %s, %s, %s)",
                (
                    str(source_id),
                    a["team_id"],
                    f"it-agents-{source_id.hex[:8]}",
                    "test",
                    True,
                ),
            )
            cur.execute(
                "INSERT INTO indicators "
                "(id, source_id, team_id, indicator_type, value, normalized_value, "
                " threat_types, confidence, severity, tags, "
                " first_seen, last_seen, collection_date, active) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    str(indicator_id),
                    str(source_id),
                    a["team_id"],
                    "domain",
                    value,
                    value,
                    Json(["phishing"]),
                    "high",
                    8,
                    Json([]),
                    now,
                    now,
                    now,
                    True,
                ),
            )
        conn.commit()

        as_a = run_tool(a, "threat_intel_query_tool", ioc_value=value)
        as_b = run_tool(b, "threat_intel_query_tool", ioc_value=value)

        assert as_a["success"] is True and as_a["total"] == 1, as_a
        [found] = as_a["indicators"]
        assert found["value"] == value and found["exact_match"] is True
        assert found["threat_types"] == ["phishing"] and found["severity"] == 8
        assert as_b["success"] is True and as_b["total"] == 0, as_b
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM indicators WHERE id = %s", (str(indicator_id),))
            cur.execute("DELETE FROM sources WHERE id = %s", (str(source_id),))
        conn.commit()
        conn.close()


def test_a_tool_without_a_caller_is_refused_in_the_container():
    """No caller, no request: the tool does not fall back to an identity of
    the service's own. A lookup tool, which the model is always given."""
    result = in_agents(
        RUN_TOOL,
        "whois_lookup_tool",
        json.dumps({"target": "example.com"}),
        stdin=json.dumps({"user_id": "", "team_id": ""}),
    )
    assert result.returncode != 0
    assert "CallerIdentityUnavailable" in result.stderr


# Runs in the agents container: the names of the tools it gives its model.
GIVEN_TOOLS = """
import json
from app.config import TEAM_DATA_TOOLS, settings
from app.tools.langchain_tools import enabled_tools
given = [tool.name for tool in enabled_tools(settings.team_data_tool_names())]
print(json.dumps({"given": given, "team_data": list(TEAM_DATA_TOOLS)}))
"""


def test_the_model_is_given_the_team_data_tools_the_stack_was_started_with():
    """Neither by default; exactly those AGENT_TEAM_DATA_TOOLS names
    otherwise. The CI stack is started with both, so the tests above run."""
    result = in_agents(GIVEN_TOOLS)
    assert result.returncode == 0, result.stderr[-800:]
    answer = json.loads(result.stdout[result.stdout.index("{") :])
    given_team_data = set(answer["given"]) & set(answer["team_data"])

    # The seven lookups are there whatever the setting.
    assert len(set(answer["given"]) - set(answer["team_data"])) == 7
    if os.getenv("AGENT_TEAM_DATA_TOOLS") is None:
        pytest.skip(
            "AGENT_TEAM_DATA_TOOLS is not set for this suite, so what the "
            f"stack was started with is unknown; it gives {sorted(given_team_data)}"
        )
    assert given_team_data == EXPECTED_TEAM_DATA_TOOLS
