"""Every shipped playbook runs to completion through the real engine (#605).

Since #597 every template in a shipped playbook compiles, and still none of
the interesting ones could finish: all_star_e2e.yml read `steps.<id>.result`
(the engine stores `output`) and a `system.timestamp` nothing provided, so it
stopped at threat_assessment; and system.evaluate returned neither of the
`verdict` and `severity` that three steps were guarded on, so those steps
never ran. Compiling a template says nothing about the names it reads.

These tests run each playbook the way production does -- start_execution,
then execute_playbook_actor -- against an in-memory Redis, with every HTTP
connector's client replaced by an httpx.MockTransport that plays the other
Wildbox services. The connectors, the engine, the context and the system
actions are the real ones. For representative inputs they assert that the
run completes and which steps ran, were skipped or failed, so a playbook that
reads a name the context does not have fails here.

The stubbed responses are checked against the services' own schemas, read
from their source in this repository, and so are the parameters the
playbooks send to each tool: a stub cannot drift into a shape the real
service never returns without failing.

The stubbed services also refuse what the real ones refuse (#616): a route
the service does not declare answers 404, and a request without the run's
gateway identity, or with the wrong X-Gateway-Secret, answers 403. Every run
is started as a user, as the execute endpoint starts it, and the tests check
that each request carried that user.
"""

import ast
import json
import os
import re
import sys
from datetime import timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
PLAYBOOKS_DIR = SERVICE_ROOT / "playbooks"
sys.path.insert(0, str(SERVICE_ROOT))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

import app.workflow_engine as engine_module  # noqa: E402
import service_contracts as contracts  # noqa: E402
from memory_redis import MemoryRedis  # noqa: E402
from app.caller import CallerIdentityUnavailable  # noqa: E402
from app.config import settings  # noqa: E402
from app.connectors import connector_registry  # noqa: E402
from app.connectors import system_connector as system_module  # noqa: E402
from app.models import ExecutionStatus  # noqa: E402
from app.playbook_parser import PlaybookParser  # noqa: E402

TOOLS_DIR = REPO_ROOT / "open-security-tools" / "app" / "tools"
TOOLS_BASE = REPO_ROOT / "open-security-tools" / "app" / "standardized_schemas.py"
AGENTS_SCHEMAS = REPO_ROOT / "open-security-agents" / "app" / "schemas.py"

# The tools the playbooks call, and the classes the tools service validates
# their input and output with (app/api/router.py, register_tool_endpoint).
TOOL_SCHEMAS = {
    "port_scanner": ("PortScannerInput", "PortScannerOutput"),
    "threat_intelligence_aggregator": (
        "ThreatIntelligenceRequest",
        "ThreatIntelligenceResponse",
    ),
    "url_analyzer": ("URLShortenerInput", "URLShortenerOutput"),
    "ip_geolocation": ("IPGeolocationInput", "IPGeolocationOutput"),
    "hash_generator": ("HashGeneratorInput", "HashGeneratorOutput"),
}

# The user a run is started by, as the execute endpoint records them from the
# gateway headers.
CALLER = {
    "user_id": "6f1c2a7e-1d0b-4c39-9a51-2f6c0f4e8b01",
    "team_id": "0b8e5d1a-7c2f-4e6a-8d3b-5a9f1c2e4d60",
    "role": "admin",
}

UNDEFINED_WARNING = "references an undefined name"


# --- The services' schemas, read from their source -------------------------


def _classes(path):
    tree = ast.parse(path.read_text())
    return {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}


def _is_required(value):
    """Required as pydantic v2 sees it: no default, or Field(...) without one."""
    if value is None:
        return True
    if not (isinstance(value, ast.Call) and getattr(value.func, "id", "") == "Field"):
        return False
    if value.args:
        first = value.args[0]
        return isinstance(first, ast.Constant) and first.value is Ellipsis
    return not any(k.arg in ("default", "default_factory") for k in value.keywords)


def schema_fields(path, class_name):
    """{field: required} of a pydantic model, its Base* parents included."""
    classes = _classes(path)
    if class_name not in classes:
        classes.update(_classes(TOOLS_BASE))
    node = classes[class_name]
    fields = {}
    for base in node.bases:
        name = getattr(base, "id", None)
        if name in ("BaseToolInput", "BaseToolOutput"):
            fields.update(schema_fields(TOOLS_BASE, name))
    for item in node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            fields[item.target.id] = _is_required(item.value)
    return fields


def conforms(payload, path, class_name):
    """Problems with ``payload`` as an instance of the named model."""
    fields = schema_fields(path, class_name)
    unknown = sorted(set(payload) - set(fields))
    missing = sorted(
        n for n, required in fields.items() if required and n not in payload
    )
    problems = []
    if unknown:
        problems.append(f"{class_name} has no {unknown}")
    if missing:
        problems.append(f"{class_name} requires {missing}")
    return problems


def tool_schemas_available():
    return TOOLS_DIR.is_dir() and AGENTS_SCHEMAS.is_file()


# --- What the other services answer -----------------------------------------


def port_scan_result(target, open_ports):
    return {
        "success": True,
        "target": target,
        "open_ports": [
            {"port": port, "protocol": "tcp", "state": "open", "service": service}
            for port, service in open_ports
        ],
        "closed_ports": 9 - len(open_ports),
        "filtered_ports": 0,
        "scan_statistics": {},
    }


def threat_intel_result(indicator, indicator_type, score):
    return {
        "success": True,
        "indicator": indicator,
        "indicator_type": indicator_type,
        "overall_threat_score": score,
        "confidence_level": "high",
        "threat_classification": "malicious" if score >= 70 else "clean",
        "sources_data": [],
        "malware_families": [],
        "threat_types": ["botnet"] if score >= 70 else [],
        "countries": [],
        "asn_info": {},
        "first_seen": None,
        "last_seen": None,
        "activity_timeline": [],
        "risk_factors": [],
        "mitigations": [],
        "related_indicators": [],
        "campaign_attribution": [],
        "timestamp": "2026-10-03T10:00:00Z",
        "processing_time_ms": 12,
    }


def url_analysis_result(url, suspicious, risk_level, threats=()):
    return {
        "success": True,
        "original_url": url,
        "final_url": url,
        "redirect_chain": [],
        "total_redirects": 0,
        "shortener_service": None,
        "security_analysis": {
            "is_suspicious": suspicious,
            "risk_level": risk_level,
            "threats_detected": list(threats),
            "reputation_score": 10 if suspicious else 90,
            "phishing_indicators": [],
            "malware_indicators": [],
        },
        "timestamp": "2026-10-03T10:00:00Z",
        "error": None,
    }


def geolocation_result(ip):
    return {
        "success": True,
        "ip_address": ip,
        "ip_version": 4,
        "is_private": False,
        "is_reserved": False,
        "geolocation": {"country": "Example Country"},
        "isp_info": {"isp": "Example ISP", "organization": "Example Org"},
        "threat_intel": None,
        "whois_info": {"registry": "RIPE"},
        "accuracy_radius": 50,
        "data_sources": ["stub"],
        "timestamp": "2026-10-03T10:00:00Z",
        "error": None,
    }


def queued_tool_task(tool, task_id="2d6b8f0e-3c1a-4e7b-9f52-8a1d0c6e4b37"):
    """What POST /api/tools/{tool}/async answers (202)."""
    return {
        "task_id": task_id,
        "status": "accepted",
        "tool_name": tool,
        "status_url": f"/api/v1/tasks/{task_id}",
        "message": "Task submitted successfully. Use task_id to check status.",
    }


def guardian_asset(ip, asset_id="7a3e9c1b-5d2f-4b8a-9e6c-1f0d2b4a6c83"):
    return {"id": asset_id, "name": f"host-{ip}", "ip_address": ip}


def analysis_task(task_id="task-1"):
    """What POST /v1/analyze answers: a task, not a verdict (202)."""
    return {
        "task_id": task_id,
        "status": "pending",
        "created_at": "2026-10-03T10:00:00Z",
        "started_at": None,
        "completed_at": None,
        "progress": None,
        "error": None,
        "result_url": f"/v1/analyze/{task_id}",
    }


class Services:
    """The Wildbox services, as seen through the connectors' HTTP clients.

    ``tools`` maps a tool name to a function of the parameters the playbook
    sent; an entry that is an int is answered with that HTTP status.
    ``assets`` are the assets Guardian knows. Every request is recorded in
    ``calls``, and refused as the real service would refuse it (see
    service_contracts.refusal); Guardian also refuses a vulnerability from a
    caller who is neither owner nor admin, as IsGatewayAdminOrReadOnly does.
    """

    def __init__(
        self, tools=None, agents=202, guardian=201, assets=(), vulnerabilities=()
    ):
        self.tools = tools or {}
        self.agents = agents
        self.guardian = guardian
        self.assets = list(assets)
        # Each with the id of its asset under "asset".
        self.vulnerabilities = list(vulnerabilities)
        self.calls = []

    def _service(self, request):
        origin = f"{request.url.scheme}://{request.url.netloc.decode()}"
        for name, url in (
            ("tools", settings.wildbox_api_url),
            ("data", settings.wildbox_data_url),
            ("guardian", settings.wildbox_guardian_url),
            ("agents", settings.wildbox_agents_url),
        ):
            parts = urlsplit(url)
            if origin == f"{parts.scheme}://{parts.netloc}":
                return name
        raise AssertionError(f"request to an unknown service: {request.url}")

    def handle(self, request):
        service = self._service(request)
        body = json.loads(request.content) if request.content else None
        self.calls.append(
            (service, request.method, request.url.path, body, dict(request.headers))
        )
        refused = contracts.refusal(service, request, settings.gateway_internal_secret)
        if refused:
            status, reason = refused
            return httpx.Response(status, json={"detail": reason})
        path = request.url.path
        if service == "tools":
            tool = path.split("/tools/", 1)[1].split("/")[0]
            answer = self.tools[tool]
            if isinstance(answer, int):
                return httpx.Response(answer, json={"detail": "unavailable"})
            if path.endswith("/async"):
                return httpx.Response(202, json=queued_tool_task(tool))
            return httpx.Response(200, json=answer(body))
        if service == "agents":
            if self.agents != 202:
                return httpx.Response(self.agents, json={"detail": "unavailable"})
            return httpx.Response(202, json=analysis_task())
        if service == "guardian" and request.method == "GET":
            # One asset, by id: 404 for an id Guardian does not hold for the
            # caller's team, as for an asset of another team.
            detail = re.fullmatch(r"/api/v1/assets/assets/([^/]+)/", path)
            if detail:
                asset = next(
                    (a for a in self.assets if a["id"] == detail.group(1)), None
                )
                if asset is None:
                    return httpx.Response(404, json={"detail": "Not found."})
                return httpx.Response(200, json=asset)
            if path == "/api/v1/vulnerabilities/":
                asset_id = request.url.params.get("asset_id")
                found = [
                    v
                    for v in self.vulnerabilities
                    if asset_id is None or v["asset"] == asset_id
                ]
                return httpx.Response(
                    200,
                    json={
                        "count": len(found),
                        "next": None,
                        "previous": None,
                        "results": found,
                    },
                )
            search = request.url.params.get("search", "")
            found = [
                a
                for a in self.assets
                if search in a["name"] or search in a["ip_address"]
            ]
            return httpx.Response(
                200,
                json={
                    "count": len(found),
                    "next": None,
                    "previous": None,
                    "results": found,
                },
            )
        if service == "guardian":
            if request.headers.get("X-Wildbox-Role") not in ("owner", "admin"):
                return httpx.Response(
                    403,
                    json={
                        "detail": "You do not have permission to perform this action."
                    },
                )
            return httpx.Response(self.guardian, json={"id": "guardian-1"})
        raise AssertionError(f"no stub for {request.method} {request.url}")

    def called(self, service, tool=None, method="POST"):
        """The bodies of the requests sent to ``service`` (and ``tool``)."""
        return [
            body
            for name, verb, path, body, _ in self.calls
            if name == service
            and verb == method
            and (tool is None or f"/tools/{tool}" in path)
        ]

    def identities(self):
        """The identity each request carried, and whether its secret was right."""
        secret = settings.gateway_internal_secret
        return [
            (
                headers.get("x-wildbox-user-id"),
                headers.get("x-wildbox-team-id"),
                headers.get("x-wildbox-role"),
                headers.get("x-gateway-secret") == secret,
            )
            for *_, headers in self.calls
        ]


# --- The engine, as production runs it --------------------------------------


@pytest.fixture(scope="module")
def playbooks():
    return PlaybookParser(playbooks_directory=str(PLAYBOOKS_DIR)).load_playbooks()


@pytest.fixture
def run(monkeypatch, playbooks):
    """Run a shipped playbook end to end; return its persisted record."""
    engine = engine_module.workflow_engine
    monkeypatch.setattr(engine, "redis_client", MemoryRedis())
    monkeypatch.setattr(engine_module.playbook_parser, "playbooks", playbooks)
    actor = engine_module.execute_playbook_actor
    monkeypatch.setattr(actor, "send", lambda *args: actor.fn(*args))
    # simple_notification waits two seconds; the wait is not under test.
    monkeypatch.setattr(system_module.time, "sleep", lambda seconds: None)

    def _run(playbook_id, trigger, services, caller=CALLER):
        transport = httpx.MockTransport(services.handle)
        for name in ("api", "wildbox", "data"):
            connector = connector_registry.get_connector(name)
            monkeypatch.setattr(connector, "client", httpx.Client(transport=transport))
        run_id = engine_module.start_execution(playbook_id, trigger, caller=caller)
        record = engine.get_execution_state(run_id)
        # Every request was made as the user who started the run.
        expected = (caller["user_id"], caller["team_id"], caller["role"], True)
        assert set(services.identities()) <= {expected}
        return record

    return _run


def outcomes(record):
    """Each step's name -> 'ran', 'skipped' or 'failed'."""
    result = {}
    for step in record.step_results:
        if step.status == ExecutionStatus.FAILED:
            result[step.step_name] = "failed"
        elif step.output == {"skipped": True, "reason": "condition_failed"}:
            result[step.step_name] = "skipped"
        else:
            result[step.step_name] = "ran"
    return result


def output(record, step_name):
    return next(s.output for s in record.step_results if s.step_name == step_name)


def assert_completed(record, playbooks, expected):
    """The run completed, every step had its turn, each as expected."""
    assert record.status == ExecutionStatus.COMPLETED, record.error
    names = [step.name for step in playbooks[record.playbook_id].steps]
    assert [s.step_name for s in record.step_results] == names
    assert outcomes(record) == expected
    # A guarded condition must not lean on the undefined-name fallback:
    # every optional reference in a shipped playbook is tested explicitly.
    assert not [line for line in record.logs if UNDEFINED_WARNING in line]


# --- simple_notification ----------------------------------------------------


def test_simple_notification_runs(run, playbooks):
    record = run("simple_notification", {"message": "hello"}, Services())
    assert_completed(
        record,
        playbooks,
        {"log_message": "ran", "wait_step": "ran", "final_log": "ran"},
    )
    assert output(record, "log_message")["message"].endswith("Received: hello")
    assert output(record, "final_log")["message"].endswith("result: logged")


def test_simple_notification_runs_without_a_message(run, playbooks):
    record = run("simple_notification", {}, Services())
    assert record.status == ExecutionStatus.COMPLETED, record.error
    assert "No message provided" in output(record, "log_message")["message"]


# --- triage_ip --------------------------------------------------------------


def ip_services(open_ports, score):
    return Services(
        tools={
            "port_scanner": lambda p: port_scan_result(p["target"], open_ports),
            "threat_intelligence_aggregator": lambda p: threat_intel_result(
                p["indicator"], p["indicator_type"], score
            ),
            "ip_geolocation": lambda p: geolocation_result(p["ip_address"]),
        }
    )


def test_triage_ip_flags_a_malicious_address(run, playbooks):
    services = ip_services([(21, "ftp"), (22, "ssh"), (80, "http")], score=85)
    record = run("triage_ip", {"ip": "203.0.113.7"}, services)
    assert_completed(
        record,
        playbooks,
        {
            "validate_ip": "ran",
            "scan_ports": "ran",
            "check_reputation": "ran",
            "whois_lookup": "ran",
            "threat_assessment": "ran",
            "generate_report": "ran",
        },
    )
    assessment = output(record, "threat_assessment")
    assert assessment["overall_result"] is True
    assert assessment["matched"] == ["high_risk", "suspicious_services"]
    report = output(record, "generate_report")["data"]
    assert report["flagged"] == "True"
    assert report["reasons"] == ["high_risk", "suspicious_services"]
    assert report["whois"]["whois_info"] == {"registry": "RIPE"}
    assert report["run_id"] == record.run_id


def test_triage_ip_clears_a_benign_address(run, playbooks):
    record = run("triage_ip", {"ip": "198.51.100.10"}, ip_services([], score=5))
    assert_completed(
        record,
        playbooks,
        {
            "validate_ip": "ran",
            "scan_ports": "ran",
            "check_reputation": "ran",
            "whois_lookup": "skipped",
            "threat_assessment": "ran",
            "generate_report": "ran",
        },
    )
    assert output(record, "threat_assessment")["overall_result"] is False
    assert output(record, "generate_report")["data"]["whois"] == {}


def test_triage_ip_stops_at_an_invalid_address(run, playbooks):
    services = ip_services([], score=0)
    record = run("triage_ip", {"ip": "999.1.1.1"}, services)
    assert_completed(
        record,
        playbooks,
        {
            "validate_ip": "ran",
            "scan_ports": "skipped",
            "check_reputation": "skipped",
            "whois_lookup": "skipped",
            "threat_assessment": "skipped",
            "generate_report": "skipped",
        },
    )
    assert services.calls == []


# --- triage_url -------------------------------------------------------------

URL = "http://login.evil.example/verify?user=a&next=%2Fhome"
URL_STEPS = [
    "validate_url",
    "url_analysis",
    "reputation_check",
    "extract_domain",
    "domain_reputation",
    "threat_verdict",
    "log_security_alert",
]


def url_services(suspicious, url_score, domain_score, risk_level="low"):
    scores = {"url": url_score, "domain": domain_score}
    return Services(
        tools={
            "url_analyzer": lambda p: url_analysis_result(
                p["shortened_url"],
                suspicious,
                risk_level,
                ["phishing"] if suspicious else (),
            ),
            "threat_intelligence_aggregator": lambda p: threat_intel_result(
                p["indicator"], p["indicator_type"], scores[p["indicator_type"]]
            ),
        }
    )


def url_outcomes(*states):
    return dict(zip(URL_STEPS, states))


def test_triage_url_alerts_on_a_malicious_url(run, playbooks):
    services = url_services(True, url_score=90, domain_score=80, risk_level="high")
    record = run("triage_url", {"url": URL}, services)
    assert_completed(record, playbooks, url_outcomes(*["ran"] * 7))
    # No blacklist: the data service has none, and nothing pretends to (#616).
    assert [c for c in services.calls if c[0] == "data"] == []
    domain_query = services.called("tools", "threat_intelligence_aggregator")[1]
    assert domain_query == {
        "indicator": "login.evil.example",
        "indicator_type": "domain",
    }
    alert = output(record, "log_security_alert")
    # Logged, not sent: system.notification delivers nothing (#639).
    assert alert["status"] == "logged"
    assert alert["delivered"] is False
    assert alert["channel"] == "security-alerts"
    message = alert["message"]
    # The URL as submitted: input templates are not HTML-escaped.
    assert f"URL: {URL}" in message
    assert "Confidence: high" in message
    assert "threats: phishing" in message
    assert "Action: none taken automatically" in message
    assert "blacklist" not in message
    assert record.run_id in message


def test_triage_url_alerts_on_two_of_three_signals(run, playbooks):
    services = url_services(True, url_score=90, domain_score=10)
    record = run("triage_url", {"url": URL}, services)
    assert record.status == ExecutionStatus.COMPLETED, record.error
    assert output(record, "threat_verdict")["matched"] == [
        "url_flagged",
        "url_reputation_bad",
    ]
    assert outcomes(record)["log_security_alert"] == "ran"
    assert "Confidence: medium" in output(record, "log_security_alert")["message"]


@pytest.mark.parametrize(
    "suspicious, url_score, domain_score",
    [(False, 5, 5), (True, 5, 5), (False, 90, 5)],
    ids=["clean", "one-signal-url", "one-signal-reputation"],
)
def test_triage_url_leaves_a_url_below_the_threshold_alone(
    run, playbooks, suspicious, url_score, domain_score
):
    services = url_services(suspicious, url_score, domain_score)
    record = run("triage_url", {"url": URL}, services)
    assert_completed(record, playbooks, url_outcomes(*["ran"] * 6, "skipped"))
    assert output(record, "threat_verdict")["overall_result"] is False


def test_triage_url_stops_at_an_invalid_url(run, playbooks):
    services = url_services(False, 0, 0)
    record = run("triage_url", {"url": "not a url"}, services)
    assert_completed(record, playbooks, url_outcomes("ran", *["skipped"] * 6))
    assert services.calls == []


# --- all_star_e2e -----------------------------------------------------------

ALL_STAR_STEPS = [
    "Validate IP Address",
    "🤖 AI-Powered Threat Analysis",
    "🔍 Network Port Scan",
    "📋 Threat Intelligence",
    "⚖️ Aggregate Threat Assessment",
    "🚨 Create Security Vulnerability",
    "📊 Generate Test Report",
]
FINDING = "🚨 Create Security Vulnerability"


def all_star_services(open_ports, score, agents=202, tools_status=None, assets=()):
    tools = {
        "port_scanner": lambda p: port_scan_result(p["target"], open_ports),
        "threat_intelligence_aggregator": lambda p: threat_intel_result(
            p["indicator"], p["indicator_type"], score
        ),
    }
    if tools_status:
        tools = {name: tools_status for name in tools}
    return Services(tools=tools, agents=agents, assets=assets)


def all_star(*states):
    return dict(zip(ALL_STAR_STEPS, states))


def test_all_star_records_a_known_threat(run, playbooks):
    asset = guardian_asset("203.0.113.7")
    services = all_star_services([(22, "ssh")], score=85, assets=[asset])
    record = run("all_star_e2e", {"ip": "203.0.113.7"}, services)
    assert_completed(record, playbooks, all_star(*["ran"] * 7))

    # The agents service's own request shape (AnalysisTaskRequest).
    [analysis] = services.called("agents")
    assert analysis == {
        "ioc": {"type": "ipv4", "value": "203.0.113.7"},
        "priority": "normal",
    }

    # Guardian is asked for the asset, then given its id.
    [lookup] = [c for c in services.calls if c[:2] == ("guardian", "GET")]
    assert lookup[2] == "/api/v1/assets/assets/"
    [finding] = services.called("guardian")
    assert finding["asset"] == asset["id"]
    assert finding["severity"] == "high"
    assert finding["priority"] == "p1"
    assert "cve_id" not in finding
    assert "Signals:** known_threat" in finding["description"]
    assert "Task ID: task-1" in finding["description"]
    assert "Open Ports: 22" in finding["description"]
    assert "Score: 85/100" in finding["description"]

    report = output(record, "📊 Generate Test Report")["data"]
    assert report["create_finding"]["output"] == {"id": "guardian-1"}
    assert report["threat_assessment"]["output"]["matched"] == ["known_threat"]


def test_all_star_records_exposed_services_as_medium(run, playbooks):
    ports = [(21, "ftp"), (22, "ssh"), (80, "http")]
    services = all_star_services(ports, 10, assets=[guardian_asset("203.0.113.8")])
    record = run("all_star_e2e", {"ip": "203.0.113.8"}, services)
    assert record.status == ExecutionStatus.COMPLETED, record.error
    assert output(record, "⚖️ Aggregate Threat Assessment")["matched"] == [
        "exposed_services"
    ]
    assert outcomes(record)[FINDING] == "ran"
    assert services.called("guardian")[0]["severity"] == "medium"


def test_all_star_creates_nothing_for_a_benign_address(run, playbooks):
    services = all_star_services([(443, "https")], score=5)
    record = run("all_star_e2e", {"ip": "198.51.100.10"}, services)
    assert_completed(
        record,
        playbooks,
        all_star("ran", "ran", "ran", "ran", "ran", "skipped", "ran"),
    )
    assert [c for c in services.calls if c[0] == "guardian"] == []
    report = output(record, "📊 Generate Test Report")["data"]
    assert report["create_finding"] == {"skipped": True}


def test_all_star_creates_nothing_for_an_address_guardian_does_not_know(run, playbooks):
    """A Guardian vulnerability belongs to an asset; there is none to use."""
    services = all_star_services([(22, "ssh")], score=85)
    record = run("all_star_e2e", {"ip": "203.0.113.11"}, services)
    assert_completed(
        record,
        playbooks,
        all_star("ran", "ran", "ran", "ran", "ran", "failed", "ran"),
    )
    assert services.called("guardian") == []
    error = next(s.error for s in record.step_results if s.step_name == FINDING)
    assert "no asset named or addressed '203.0.113.11'" in error


def test_all_star_finding_is_refused_to_a_member(run, playbooks):
    """Guardian lets owners and admins create vulnerabilities, as the caller."""
    member = {**CALLER, "role": "member"}
    services = all_star_services(
        [(22, "ssh")], score=85, assets=[guardian_asset("203.0.113.7")]
    )
    record = run("all_star_e2e", {"ip": "203.0.113.7"}, services, caller=member)
    assert record.status == ExecutionStatus.COMPLETED, record.error
    assert outcomes(record)[FINDING] == "failed"
    error = next(s.error for s in record.step_results if s.step_name == FINDING)
    assert "answered 403" in error


def test_all_star_carries_on_when_the_services_fail(run, playbooks):
    """The enrichment steps fail under on_failure: continue; the run completes."""
    services = all_star_services([], 0, agents=503, tools_status=500)
    record = run("all_star_e2e", {"ip": "203.0.113.9"}, services)
    assert_completed(
        record,
        playbooks,
        all_star("ran", "failed", "failed", "failed", "ran", "skipped", "ran"),
    )
    assert output(record, "⚖️ Aggregate Threat Assessment")["overall_result"] is False
    report = output(record, "📊 Generate Test Report")["data"]
    assert report["port_scan"]["status"] == "failed"
    assert report["port_scan"]["output"] is None
    # Each failing call was sent once: the connectors do not retry.
    assert len(services.called("agents")) == 1
    assert len(services.called("tools", "port_scanner")) == 1


def test_all_star_reports_a_threat_when_the_ai_service_is_down(run, playbooks):
    services = all_star_services(
        [(22, "ssh")], score=90, agents=503, assets=[guardian_asset("203.0.113.10")]
    )
    record = run("all_star_e2e", {"ip": "203.0.113.10"}, services)
    assert outcomes(record)["🤖 AI-Powered Threat Analysis"] == "failed"
    assert outcomes(record)[FINDING] == "ran"
    [finding] = services.called("guardian")
    assert "Task ID: not started" in finding["description"]


def test_all_star_stops_at_an_invalid_address(run, playbooks):
    services = all_star_services([], 0)
    record = run("all_star_e2e", {"ip": "not-an-ip"}, services)
    assert_completed(record, playbooks, all_star("ran", *["skipped"] * 6))
    assert services.calls == []


# --- hash_evidence ----------------------------------------------------------


def test_hash_evidence_queues_the_hashing_as_the_caller(run, playbooks):
    services = Services(tools={"hash_generator": lambda p: {}})
    record = run("hash_evidence", {"text": "powershell -enc AAAA"}, services)
    assert_completed(record, playbooks, {"queue_hashing": "ran", "report": "ran"})
    [(service, method, path, body, headers)] = services.calls
    assert (service, method, path) == (
        "tools",
        "POST",
        "/api/tools/hash_generator/async",
    )
    # The tool's input itself, not wrapped: the tools service validates the
    # body as the tool's input schema.
    assert body == {
        "input_text": "powershell -enc AAAA",
        "hash_types": ["sha256", "sha512"],
    }
    assert headers["x-wildbox-user-id"] == CALLER["user_id"]
    report = output(record, "report")["data"]
    assert report["task_id"] == queued_tool_task("hash_generator")["task_id"]
    assert report["status_url"] == f"/api/v1/tasks/{report['task_id']}"


def test_hash_evidence_without_text_fails_before_any_call(run, playbooks):
    services = Services(tools={"hash_generator": lambda p: {}})
    record = run("hash_evidence", {}, services)
    assert record.status == ExecutionStatus.FAILED
    assert services.calls == []


# --- asset_vulnerabilities --------------------------------------------------
#
# The one shipped playbook that only calls Guardian, and does so on every
# run. Every Guardian action was answered 301 on the running stack (#707):
# the connectors called it over plain HTTP without X-Forwarded-Proto, and
# Guardian redirects such a request to https://. The stand-in answers that
# redirect as Guardian does (service_contracts.https_redirect), so these
# fail if the header goes.

ASSET_ID = "7a3e9c1b-5d2f-4b8a-9e6c-1f0d2b4a6c83"
OTHER_ASSET_ID = "1c9e7a3b-2f5d-4a8b-9c6e-3d0f1b2a4c68"


def asset_services():
    return Services(
        assets=[
            guardian_asset("203.0.113.7", ASSET_ID),
            guardian_asset("203.0.113.8", OTHER_ASSET_ID),
        ],
        vulnerabilities=[
            {"id": "v-1", "asset": ASSET_ID, "title": "OpenSSH regreSSHion"},
            {"id": "v-2", "asset": ASSET_ID, "title": "Outdated TLS configuration"},
            {"id": "v-3", "asset": OTHER_ASSET_ID, "title": "Another asset's finding"},
        ],
    )


def test_asset_vulnerabilities_reads_the_asset_and_its_findings(run, playbooks):
    services = asset_services()
    record = run("asset_vulnerabilities", {"asset_id": ASSET_ID}, services)

    assert_completed(
        record,
        playbooks,
        {"read_asset": "ran", "list_vulnerabilities": "ran", "report": "ran"},
    )
    assert [(s, m, p) for s, m, p, _, _ in services.calls] == [
        ("guardian", "GET", f"/api/v1/assets/assets/{ASSET_ID}/"),
        ("guardian", "GET", "/api/v1/vulnerabilities/"),
    ]
    assert output(record, "read_asset")["name"] == "host-203.0.113.7"
    listed = output(record, "list_vulnerabilities")
    assert listed["count"] == 2
    assert output(record, "report")["data"] == {
        "run_id": record.run_id,
        "asset_id": ASSET_ID,
        "asset_name": "host-203.0.113.7",
        "vulnerabilities": "2",
        "titles": "OpenSSH regreSSHion; Outdated TLS configuration",
    }


def test_asset_vulnerabilities_tells_guardian_the_run_came_over_https(run, playbooks):
    """Guardian redirects plain HTTP without this header (#707)."""
    services = asset_services()
    record = run("asset_vulnerabilities", {"asset_id": ASSET_ID}, services)

    assert record.status == ExecutionStatus.COMPLETED, record.error
    assert len(services.calls) == 2
    for *_, headers in services.calls:
        assert headers["x-forwarded-proto"] == "https"


def test_asset_vulnerabilities_fails_for_an_asset_the_caller_cannot_see(run, playbooks):
    """Guardian answers 404 for another team's asset as for none; the run
    stops there and lists nothing."""
    services = asset_services()
    unknown = "5d2f7a3e-9c1b-4b8a-8e6c-2b4a6c831f0d"
    record = run("asset_vulnerabilities", {"asset_id": unknown}, services)

    assert record.status == ExecutionStatus.FAILED
    assert "404" in record.error
    assert [p for _, _, p, _, _ in services.calls] == [
        f"/api/v1/assets/assets/{unknown}/"
    ]


@pytest.mark.parametrize(
    "trigger", [{}, {"asset_id": "not-a-uuid"}, {"asset_id": "../x"}]
)
def test_asset_vulnerabilities_without_a_valid_id_sends_nothing(
    run, playbooks, trigger
):
    services = asset_services()
    record = run("asset_vulnerabilities", trigger, services)

    assert record.status == ExecutionStatus.FAILED
    assert services.calls == []


# --- The run's caller -------------------------------------------------------


def test_every_request_of_a_run_carries_its_caller(run, playbooks):
    services = ip_services([(21, "ftp"), (22, "ssh")], score=85)
    record = run("triage_ip", {"ip": "203.0.113.7"}, services)
    assert record.status == ExecutionStatus.COMPLETED, record.error
    assert len(services.calls) == 3
    assert set(services.identities()) == {
        (CALLER["user_id"], CALLER["team_id"], CALLER["role"], True)
    }


@pytest.mark.parametrize(
    "caller",
    [None, {}, {"user_id": CALLER["user_id"]}, {"team_id": CALLER["team_id"]}],
    ids=["none", "empty", "no-team", "no-user"],
)
def test_a_run_is_not_started_without_a_complete_caller(run, caller):
    with pytest.raises(CallerIdentityUnavailable):
        run("triage_ip", {"ip": "203.0.113.7"}, ip_services([], 0), caller=caller)
    store = engine_module.workflow_engine.redis_client
    assert store.hashes == {} and store.strings == {}


def test_a_run_without_a_caller_fails_before_any_call(monkeypatch, playbooks):
    """A message without a caller -- queued by an older version, say."""
    engine = engine_module.workflow_engine
    monkeypatch.setattr(engine, "redis_client", MemoryRedis())
    monkeypatch.setattr(engine_module.playbook_parser, "playbooks", playbooks)
    services = ip_services([(22, "ssh")], 85)
    transport = httpx.MockTransport(services.handle)
    for name in ("api", "wildbox", "data"):
        connector = connector_registry.get_connector(name)
        monkeypatch.setattr(connector, "client", httpx.Client(transport=transport))

    result = engine_module.execute_playbook_actor.fn(
        "run-1", "triage_ip", {"ip": "203.0.113.7"}
    )

    assert result["status"] == ExecutionStatus.FAILED
    assert "no caller identity" in result["error"]
    assert result["step_results"] == []
    assert services.calls == []


def test_the_caller_does_not_outlive_its_run(run, playbooks):
    from app.caller import current_caller

    run("simple_notification", {}, Services())
    assert current_caller() is None


# --- The run context --------------------------------------------------------


def test_the_context_carries_the_run(run):
    record = run("simple_notification", {}, Services())
    started = record.start_time.replace(tzinfo=timezone.utc).isoformat()
    assert record.context["run"] == {
        "id": record.run_id,
        "playbook_id": "simple_notification",
        "started_at": started,
    }


def test_a_step_reading_a_name_the_context_lacks_fails_the_run(
    run, playbooks, monkeypatch
):
    """The defect class: `result` for `output`, as all_star_e2e had it."""
    playbook = playbooks["simple_notification"].model_copy(deep=True)
    playbook.steps[2].input["message"] = "{{ steps.log_message.result.status }}"
    monkeypatch.setattr(
        engine_module.playbook_parser,
        "playbooks",
        {**playbooks, "simple_notification": playbook},
    )
    record = run("simple_notification", {}, Services())
    assert record.status == ExecutionStatus.FAILED
    assert outcomes(record)["final_log"] == "failed"


# --- The stubs and the parameters match the real services ------------------


requires_schemas = pytest.mark.skipif(
    not tool_schemas_available(), reason="the other services' sources are not here"
)


@requires_schemas
@pytest.mark.parametrize(
    "tool, payload",
    [
        ("port_scanner", port_scan_result("203.0.113.7", [(22, "ssh")])),
        ("threat_intelligence_aggregator", threat_intel_result("x", "ip", 1)),
        ("url_analyzer", url_analysis_result(URL, True, "high")),
        ("ip_geolocation", geolocation_result("203.0.113.7")),
    ],
)
def test_the_stubbed_tool_results_match_the_tools_schemas(tool, payload):
    schemas = TOOLS_DIR / tool / "schemas.py"
    assert not conforms(payload, schemas, TOOL_SCHEMAS[tool][1])


@requires_schemas
def test_the_nested_results_the_playbooks_read_match_too():
    url_schemas = TOOLS_DIR / "url_analyzer" / "schemas.py"
    analysis = url_analysis_result(URL, True, "high")["security_analysis"]
    assert not conforms(analysis, url_schemas, "SecurityAnalysis")
    port = port_scan_result("x", [(22, "ssh")])["open_ports"][0]
    assert not conforms(port, TOOLS_BASE, "NetworkPort")


@requires_schemas
def test_the_stubbed_analysis_task_matches_the_agents_schema():
    assert not conforms(analysis_task(), AGENTS_SCHEMAS, "AnalysisTaskStatus")


@requires_schemas
def test_the_analysis_request_matches_the_agents_schema():
    """What analyze_ioc sends is an AnalysisTaskRequest (#616)."""
    services = all_star_services([], 0)
    connector = connector_registry.get_connector("wildbox")
    original = connector.client
    connector.client = httpx.Client(transport=httpx.MockTransport(services.handle))
    try:
        from app.caller import run_as

        with run_as(CALLER):
            connector.analyze_ioc("ipv4", "203.0.113.7")
    finally:
        connector.client = original
    [request] = services.called("agents")
    assert not conforms(request, AGENTS_SCHEMAS, "AnalysisTaskRequest")
    assert not conforms(request["ioc"], AGENTS_SCHEMAS, "IOCInput")


@requires_schemas
@pytest.mark.parametrize(
    "playbook_id", ["triage_ip", "triage_url", "all_star_e2e", "hash_evidence"]
)
def test_the_playbooks_send_each_tool_the_parameters_it_takes(playbooks, playbook_id):
    """A misspelled or invented parameter is refused by the tool with a 422."""
    problems = []
    for step in playbooks[playbook_id].steps:
        if step.action not in ("api.run_tool", "wildbox.run_tool"):
            continue
        tool = step.input["tool_name"]
        assert (
            tool in TOOL_SCHEMAS
        ), f"{step.name}: no tool named {tool!r} is known here"
        schemas = TOOLS_DIR / tool / "schemas.py"
        problems += [
            f"{step.name}: {p}"
            for p in conforms(step.input["params"], schemas, TOOL_SCHEMAS[tool][0])
        ]
    assert not problems
