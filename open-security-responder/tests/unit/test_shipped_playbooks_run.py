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
"""

import ast
import json
import os
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
    sent; an entry that is an int is answered with that HTTP status. Every
    request is recorded in ``calls``.
    """

    def __init__(self, tools=None, agents=202, guardian=201, data=201):
        self.tools = tools or {}
        self.agents = agents
        self.guardian = guardian
        self.data = data
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
        self.calls.append((service, request.url.path, body))
        if service == "tools":
            tool = request.url.path.split("/tools/", 1)[1].split("/")[0]
            answer = self.tools[tool]
            if isinstance(answer, int):
                return httpx.Response(answer, json={"detail": "unavailable"})
            return httpx.Response(200, json=answer(body["params"]))
        if service == "agents":
            if self.agents != 202:
                return httpx.Response(self.agents, json={"detail": "unavailable"})
            return httpx.Response(202, json=analysis_task())
        status = getattr(self, service)
        return httpx.Response(status, json={"id": f"{service}-1"})

    def called(self, service, tool=None):
        return [
            body
            for name, path, body in self.calls
            if name == service and (tool is None or f"/tools/{tool}" in path)
        ]


# --- The engine, as production runs it --------------------------------------


class FakeRedis:
    """The part of redis-py the engine uses, in memory."""

    def __init__(self):
        self.hashes, self.lists, self.strings = {}, {}, {}

    def hset(self, key, mapping):
        # As redis-py encodes: a str (an ExecutionStatus too) by its value.
        self.hashes.setdefault(key, {}).update(
            {
                k: (
                    v
                    if isinstance(v, bytes)
                    else str.encode(v) if isinstance(v, str) else str(v).encode()
                )
                for k, v in mapping.items()
            }
        )

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def expire(self, key, seconds):
        pass

    def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)

    def set(self, key, value, ex=None):
        self.strings[key] = str(value).encode()

    def get(self, key):
        return self.strings.get(key)

    def pipeline(self):
        return self

    def execute(self):
        return []


@pytest.fixture(scope="module")
def playbooks():
    return PlaybookParser(playbooks_directory=str(PLAYBOOKS_DIR)).load_playbooks()


@pytest.fixture
def run(monkeypatch, playbooks):
    """Run a shipped playbook end to end; return its persisted record."""
    engine = engine_module.workflow_engine
    monkeypatch.setattr(engine, "redis_client", FakeRedis())
    monkeypatch.setattr(engine_module.playbook_parser, "playbooks", playbooks)
    actor = engine_module.execute_playbook_actor
    monkeypatch.setattr(actor, "send", lambda *args: actor.fn(*args))
    # simple_notification waits two seconds; the wait is not under test.
    monkeypatch.setattr(system_module.time, "sleep", lambda seconds: None)

    def _run(playbook_id, trigger, services):
        transport = httpx.MockTransport(services.handle)
        for name in ("api", "wildbox", "data"):
            connector = connector_registry.get_connector(name)
            monkeypatch.setattr(connector, "client", httpx.Client(transport=transport))
        run_id = engine_module.start_execution(playbook_id, trigger, team_id="team-1")
        return engine.get_execution_state(run_id)

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


def test_triage_url_blacklists_a_malicious_url(run, playbooks):
    services = url_services(True, url_score=90, domain_score=80, risk_level="high")
    record = run("triage_url", {"url": URL}, services)
    assert_completed(
        record,
        playbooks,
        {
            "validate_url": "ran",
            "url_analysis": "ran",
            "reputation_check": "ran",
            "extract_domain": "ran",
            "domain_reputation": "ran",
            "threat_verdict": "ran",
            "add_to_blacklist": "ran",
            "notify_security_team": "ran",
        },
    )
    [entry] = services.called("data")
    # The URL as submitted: input templates are not HTML-escaped.
    assert entry["value"] == URL
    assert entry["type"] == "url"
    assert entry["confidence"] == "high"
    assert "url_flagged" in entry["reason"]
    domain_query = services.called("tools", "threat_intelligence_aggregator")[1]
    assert domain_query["params"] == {
        "indicator": "login.evil.example",
        "indicator_type": "domain",
    }
    message = output(record, "notify_security_team")["message"]
    assert f"URL: {URL}" in message
    assert "threats: phishing" in message
    assert record.run_id in message


def test_triage_url_blacklists_on_two_of_three_signals(run, playbooks):
    services = url_services(True, url_score=90, domain_score=10)
    record = run("triage_url", {"url": URL}, services)
    assert record.status == ExecutionStatus.COMPLETED, record.error
    assert output(record, "threat_verdict")["matched"] == [
        "url_flagged",
        "url_reputation_bad",
    ]
    assert outcomes(record)["add_to_blacklist"] == "ran"
    assert services.called("data")[0]["confidence"] == "medium"


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
    assert_completed(
        record,
        playbooks,
        {
            "validate_url": "ran",
            "url_analysis": "ran",
            "reputation_check": "ran",
            "extract_domain": "ran",
            "domain_reputation": "ran",
            "threat_verdict": "ran",
            "add_to_blacklist": "skipped",
            "notify_security_team": "skipped",
        },
    )
    assert output(record, "threat_verdict")["overall_result"] is False
    assert services.called("data") == []


def test_triage_url_stops_at_an_invalid_url(run, playbooks):
    services = url_services(False, 0, 0)
    record = run("triage_url", {"url": "not a url"}, services)
    assert_completed(
        record,
        playbooks,
        {
            "validate_url": "ran",
            "url_analysis": "skipped",
            "reputation_check": "skipped",
            "extract_domain": "skipped",
            "domain_reputation": "skipped",
            "threat_verdict": "skipped",
            "add_to_blacklist": "skipped",
            "notify_security_team": "skipped",
        },
    )
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


def all_star_services(open_ports, score, agents=202, tools_status=None):
    tools = {
        "port_scanner": lambda p: port_scan_result(p["target"], open_ports),
        "threat_intelligence_aggregator": lambda p: threat_intel_result(
            p["indicator"], p["indicator_type"], score
        ),
    }
    if tools_status:
        tools = {name: tools_status for name in tools}
    return Services(tools=tools, agents=agents)


def all_star(*states):
    return dict(zip(ALL_STAR_STEPS, states))


def test_all_star_records_a_known_threat(run, playbooks):
    services = all_star_services([(22, "ssh")], score=85)
    record = run("all_star_e2e", {"ip": "203.0.113.7"}, services)
    assert_completed(record, playbooks, all_star(*["ran"] * 7))

    [analysis] = services.called("agents")
    assert analysis["ioc_value"] == "203.0.113.7"
    assert analysis["context"]["run_id"] == record.run_id
    assert analysis["context"]["requested_at"] == record.context["run"]["started_at"]

    [finding] = services.called("guardian")
    assert finding["severity"] == "high"
    assert finding["asset_name"] == "203.0.113.7"
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
    record = run("all_star_e2e", {"ip": "203.0.113.8"}, all_star_services(ports, 10))
    assert record.status == ExecutionStatus.COMPLETED, record.error
    assert output(record, "⚖️ Aggregate Threat Assessment")["matched"] == [
        "exposed_services"
    ]
    assert outcomes(record)["🚨 Create Security Vulnerability"] == "ran"


def test_all_star_creates_nothing_for_a_benign_address(run, playbooks):
    services = all_star_services([(443, "https")], score=5)
    record = run("all_star_e2e", {"ip": "198.51.100.10"}, services)
    assert_completed(
        record,
        playbooks,
        all_star("ran", "ran", "ran", "ran", "ran", "skipped", "ran"),
    )
    assert services.called("guardian") == []
    report = output(record, "📊 Generate Test Report")["data"]
    assert report["create_finding"] == {"skipped": True}


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


def test_all_star_reports_a_threat_when_the_ai_service_is_down(run, playbooks):
    services = all_star_services([(22, "ssh")], score=90, agents=503)
    record = run("all_star_e2e", {"ip": "203.0.113.10"}, services)
    assert outcomes(record)["🤖 AI-Powered Threat Analysis"] == "failed"
    assert outcomes(record)["🚨 Create Security Vulnerability"] == "ran"
    [finding] = services.called("guardian")
    assert "Task ID: not started" in finding["description"]


def test_all_star_stops_at_an_invalid_address(run, playbooks):
    services = all_star_services([], 0)
    record = run("all_star_e2e", {"ip": "not-an-ip"}, services)
    assert_completed(record, playbooks, all_star("ran", *["skipped"] * 6))
    assert services.calls == []


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
@pytest.mark.parametrize("playbook_id", ["triage_ip", "triage_url", "all_star_e2e"])
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
