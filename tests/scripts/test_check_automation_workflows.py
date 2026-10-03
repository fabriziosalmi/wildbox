"""Tests for check_automation_workflows.py, the guard on the n8n workflows' API calls.

The executive dashboard workflow called /api/v1/dashboard/executive-summary
after #578 removed it, and /api/v1/cspm/summary, which never existed (#592).
Nothing failed: the workflows are JSON that only n8n runs. The guard resolves
each HTTP node's URL against the gateway configuration and the target
service's route table. These run it on the repository's own workflows and
gateway configuration, on a fixture that calls the removed endpoint, and on
workflows written in each test.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_automation_workflows.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "automation_workflows"

spec = importlib.util.spec_from_file_location("check_automation_workflows", SCRIPT)
caw = importlib.util.module_from_spec(spec)
# Registered before it runs: dataclasses look their module up in sys.modules.
sys.modules[spec.name] = caw
spec.loader.exec_module(caw)

GATEWAY = "={{ $env.WILDBOX_API_GATEWAY_URL }}"
API_KEY = {
    "parameters": [{"name": "X-API-Key", "value": "={{ $env.WILDBOX_API_KEY }}"}]
}


def http_node(
    url, method=None, headers=API_KEY, type_version=4.2, send_headers=True, name="Call"
):
    params = {"url": url, "options": {}}
    if method:
        params["method"] = method
    if headers is not None:
        params["headerParameters"] = headers
        params["sendHeaders"] = send_headers
    return {
        "name": name,
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": type_version,
        "parameters": params,
    }


def write_workflow(directory, *nodes, name="wf.json"):
    path = directory / name
    path.write_text(
        json.dumps({"name": "test", "nodes": list(nodes), "connections": {}})
    )
    return path


@pytest.fixture(scope="module")
def checker():
    return caw.Checker(ROOT, ROOT / caw.GATEWAY_CONF)


def problems_for(checker, tmp_path, *nodes):
    _, problems = checker.check_workflow(write_workflow(tmp_path, *nodes))
    return problems


# -- the repository as it is -------------------------------------------------


def test_repository_workflows_pass(capsys):
    assert caw.main(["--root", str(ROOT)]) == 0
    assert "OK:" in capsys.readouterr().out


def test_removed_endpoint_fixture_fails(capsys):
    """The call #592 is about: the endpoint #578 removed must break the build."""
    code = caw.main(["--root", str(ROOT), "--workflows", str(FIXTURES)])
    err = capsys.readouterr().err
    assert code == 1
    assert "Get Executive Summary" in err
    assert "open-security-cspm has no route /api/v1/dashboard/executive-summary" in err


def test_empty_workflow_directory_fails(tmp_path, capsys):
    assert caw.main(["--root", str(ROOT), "--workflows", str(tmp_path)]) == 1
    assert "no workflow JSON" in capsys.readouterr().err


def test_unreadable_workflow_fails(checker, tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{ not json")
    _, problems = checker.check_workflow(bad)
    assert len(problems) == 1 and "cannot read the workflow" in problems[0]


# -- routes ------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/cspm/dashboard/summary",
        "/api/v1/cspm/compliance/summary?days=30",
        "/api/v1/cspm/compliance/findings",
        "/api/v1/cspm/scans/{{ $json.scan_id }}/report",
        "/api/v1/responder/playbooks",
        "/api/v1/data/indicators/search",
    ],
)
def test_existing_routes_pass(checker, tmp_path, path):
    assert problems_for(checker, tmp_path, http_node(GATEWAY + path)) == []


def test_post_to_an_existing_post_route_passes(checker, tmp_path):
    node = http_node(GATEWAY + "/api/v1/agents/analyze", method="POST")
    assert problems_for(checker, tmp_path, node) == []


@pytest.mark.parametrize(
    "path, reason",
    [
        # Never existed (the old executive dashboard).
        ("/api/v1/cspm/summary", "open-security-cspm has no route /api/v1/summary"),
        # No gateway prefix: the catch-all answers 404.
        ("/api/v1/sensors/summary", "location /api/ answers 404 itself"),
        ("/api/data/v1/reports", "location /api/ answers 404 itself"),
        # The prefix exists, the service route does not.
        (
            "/api/v1/responder/incidents",
            "open-security-responder has no route /v1/incidents",
        ),
        # An expression may stand for a path parameter, not for a fixed segment.
        ("/api/v1/cspm/{{ $json.kind }}/summary", "open-security-cspm has no route"),
    ],
)
def test_missing_routes_fail(checker, tmp_path, path, reason):
    problems = problems_for(checker, tmp_path, http_node(GATEWAY + path))
    assert len(problems) == 1
    assert reason in problems[0]


def test_wrong_method_fails(checker, tmp_path):
    node = http_node(GATEWAY + "/api/v1/cspm/dashboard/summary", method="POST")
    problems = problems_for(checker, tmp_path, node)
    assert len(problems) == 1 and "for GET, not POST" in problems[0]


def test_method_defaults_to_get_like_n8n(checker, tmp_path):
    # n8n's HTTP Request node sends GET when no method is set, including the
    # version 1 nodes that put the body under options and no method at all.
    node = http_node(GATEWAY + "/api/v1/agents/analyze", type_version=1)
    problems = problems_for(checker, tmp_path, node)
    assert len(problems) == 1 and "not GET" in problems[0]


def test_method_as_expression_fails(checker, tmp_path):
    node = http_node(
        GATEWAY + "/api/v1/cspm/dashboard/summary", method="={{ $json.verb }}"
    )
    assert "method is an expression" in problems_for(checker, tmp_path, node)[0]


def test_upstream_without_route_table_fails(checker, tmp_path):
    # guardian is Django; the guard has no route table for it, so it cannot
    # vouch for the call and says so.
    problems = problems_for(
        checker, tmp_path, http_node(GATEWAY + "/api/v1/guardian/assets/")
    )
    assert len(problems) == 1 and "no route table" in problems[0]


# -- URL resolution ----------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://open-security-cspm:8019/api/v1/compliance/summary",
        "http://wildbox-gateway:8000/api/v1/alerts",
        "=http://redis:6379/INCR/key_{{ $json.ip }}",
        "https://api.wildbox.local/api/v1/cspm/dashboard/summary",
    ],
)
def test_direct_internal_calls_fail(checker, tmp_path, url):
    problems = problems_for(checker, tmp_path, http_node(url))
    assert len(problems) == 1 and "internal host" in problems[0]


@pytest.mark.parametrize(
    "url",
    [
        '={{$node["Schedule Trigger"].json["webhook_url"]}}/api/v1/cspm/dashboard/summary',
        "={{ $json.slack_webhook_url }}",
        "={{ $env.WILDBOX_DATA_URL }}/api/v1/stats",
    ],
)
def test_unresolvable_bases_fail(checker, tmp_path, url):
    problems = problems_for(checker, tmp_path, http_node(url))
    assert len(problems) == 1


def test_known_webhook_variable_passes(checker, tmp_path):
    node = http_node("={{ $env.SLACK_WEBHOOK_URL }}", method="POST", headers=None)
    assert problems_for(checker, tmp_path, node) == []


def test_public_host_with_expression_in_path_passes(checker, tmp_path):
    node = http_node(
        "=https://services.nvd.nist.gov/rest/json/cves/2.0?x={{ $json.q }}",
        headers=None,
    )
    assert problems_for(checker, tmp_path, node) == []


def test_bracket_form_of_the_gateway_variable_resolves(checker, tmp_path):
    node = http_node(
        "={{ $env['WILDBOX_API_GATEWAY_URL'] }}/api/v1/cspm/dashboard/summary"
    )
    assert problems_for(checker, tmp_path, node) == []


# -- authentication ----------------------------------------------------------


def test_bearer_header_passes(checker, tmp_path):
    headers = {
        "parameters": [
            {"name": "Authorization", "value": "=Bearer {{ $env.WILDBOX_TOKEN }}"}
        ]
    }
    node = http_node(GATEWAY + "/api/v1/cspm/dashboard/summary", headers=headers)
    assert problems_for(checker, tmp_path, node) == []


@pytest.mark.parametrize(
    "headers, send_headers, reason",
    [
        (None, True, "neither an X-API-Key"),
        (
            {"parameters": [{"name": "Authorization", "value": "Basic abc"}]},
            True,
            "neither an X-API-Key",
        ),
        ({"parameters": [{"name": "Cookie", "value": "auth_token=x"}]}, True, "Cookie"),
        (API_KEY, False, "sendHeaders is off"),
    ],
)
def test_gateway_calls_must_authenticate(
    checker, tmp_path, headers, send_headers, reason
):
    node = http_node(
        GATEWAY + "/api/v1/cspm/dashboard/summary",
        headers=headers,
        send_headers=send_headers,
    )
    problems = problems_for(checker, tmp_path, node)
    assert len(problems) == 1 and reason in problems[0]


def test_non_http_nodes_are_ignored(checker, tmp_path):
    node = {
        "name": "Code",
        "type": "n8n-nodes-base.code",
        "parameters": {"jsCode": "return []"},
    }
    count, problems = checker.check_workflow(write_workflow(tmp_path, node))
    assert (count, problems) == (0, [])


# -- nginx matching ----------------------------------------------------------

CONF = """
upstream svc_a {
    server host-a:1 max_fails=3;
    server host-a-backup:1 backup;
}

server {
    listen 80;
    location / {
        return 301 https://example$request_uri;
    }
}

server {
    listen 443 ssl;
    location = /api/v1/exact {
        proxy_pass http://svc_a/health;
    }
    location /api/v1/a/ {
        proxy_pass http://svc_a/api/v1/;
    }
    location ^~ /api/v1/a/stop/ {
        proxy_pass http://svc_a/stopped/;
    }
    location ~ ^/api/v1/a/(.*)$ {
        proxy_pass http://svc_a/regex/$1$is_args$args;
    }
    location ~ ^/api/v1/re/(.*)$ {
        proxy_pass http://svc_a/v1/$1$is_args$args;
    }
    # location /api/v1/commented/ {
    #     proxy_pass http://svc_a/;
    # }
    location /api/ {
        return 404 '{"error":"endpoint_not_found"}';
    }
}
"""


@pytest.fixture(scope="module")
def parsed():
    return caw.parse_gateway(CONF)


def resolve(parsed, path):
    locations, _ = parsed
    loc, found = caw.match_location(locations, path)
    if loc is None or loc.proxy_pass is None:
        return loc
    return caw.upstream_target(loc, path, found)


def test_only_the_https_server_counts(parsed):
    locations, upstreams = parsed
    assert all(loc.pattern != "/" for loc in locations)
    assert upstreams == {"svc_a": "host-a"}


def test_exact_location_wins(parsed):
    assert resolve(parsed, "/api/v1/exact") == ("svc_a", "/health")


def test_regex_beats_plain_prefix(parsed):
    # nginx checks regexes after the longest plain prefix, and a regex match wins.
    assert resolve(parsed, "/api/v1/a/x") == ("svc_a", "/regex/x")


def test_caret_tilde_prefix_stops_the_regex_search(parsed):
    assert resolve(parsed, "/api/v1/a/stop/y") == ("svc_a", "/stopped/y")


def test_regex_capture_is_substituted(parsed):
    assert resolve(parsed, "/api/v1/re/analyze") == ("svc_a", "/v1/analyze")


def test_commented_location_is_no_route(parsed):
    loc = resolve(parsed, "/api/v1/commented/x")
    assert loc.pattern == "/api/" and loc.answers == "404"


def test_conf_without_https_server_is_an_error():
    with pytest.raises(ValueError):
        caw.parse_gateway("server {\n    listen 80;\n}\n")


@pytest.mark.parametrize(
    "template, path, expected",
    [
        ("/api/v1/scans/{scan_id}", "/api/v1/scans/abc", True),
        ("/api/v1/scans/{scan_id}", "/api/v1/scans/" + caw.PLACEHOLDER, True),
        ("/api/v1/scans/{scan_id}", "/api/v1/scans/", False),
        ("/api/v1/scans/{scan_id}", "/api/v1/scans/a/b", False),
        ("/api/v1/files/{rest:path}", "/api/v1/files/a/b", True),
        ("/api/v1/checks", "/api/v1/" + caw.PLACEHOLDER, False),
        ("/api/v1/checks", "/api/v1/checks/", True),
    ],
)
def test_template_matching(template, path, expected):
    assert caw.template_matches(template, path) is expected
