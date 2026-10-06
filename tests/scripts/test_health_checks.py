"""The health scripts require a 2xx from each service's real health URL, and
the stale API-doc generators are gone (#656).

`make health` probed guardian at /health with `curl -s`. guardian is a Django
service whose route is /health/: /health answers 301, and curl without -f
exits 0 on any status, so guardian counted as healthy while /health/ answered
503. The script also exited 0 whatever it found. scripts/wait-for-services.sh
waited for guardian on port 8003, where nothing listens.

The scripts now share one table, scripts/lib/health_endpoints.sh. These tests
run the real scripts with the real curl against a stub HTTP server: a curl
configuration file (`connect-to`) sends every connection to the stub, which
answers by the Host header, so the scripts need no test hook and the URLs
they request are the ones in the table. Docker, where a script calls it, is a
stub on PATH. No stack is involved.
"""

import http.server
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import threading
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE = REPO_ROOT / "scripts" / "lib" / "health_endpoints.sh"
HEALTH = REPO_ROOT / "scripts" / "shell-scripts" / "comprehensive_health_check.sh"
WAIT = REPO_ROOT / "scripts" / "wait-for-services.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("curl") is None, reason="the scripts under test call curl"
)


def _table():
    """[(name, url, profile)] as the scripts read it."""
    out = subprocess.run(
        ["bash", "-c", f'. "{TABLE}"; wb_health_endpoints'],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [tuple(line.split("|")) for line in out.splitlines() if line.strip()]


def _port_and_path(url):
    match = re.fullmatch(r"http://localhost(?::(\d+))?(/.*)", url)
    assert match, url
    return int(match.group(1) or 80), match.group(2)


ENDPOINTS = _table()
PORT = {name: _port_and_path(url)[0] for name, url, _ in ENDPOINTS}
PATH_OF = {name: _port_and_path(url)[1] for name, url, _ in ENDPOINTS}
DEFAULT_STACK = [name for name, _, profile in ENDPOINTS if not profile]
PROFILE_SERVICES = {name: profile for name, _, profile in ENDPOINTS if profile}

# Made up for these tests. Never a real secret.
REDIS_PASSWORD = "made-up-redis-password"


class Stub:
    """An HTTP server standing for every service, told apart by Host."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.answers = {}
        self.down = set(PROFILE_SERVICES)
        self.requests = []
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 (http.server's name)
                host = self.headers.get("Host", "")
                port = int(host.rsplit(":", 1)[1]) if ":" in host else 80
                stub.requests.append((port, self.path))
                status, headers = stub.answers.get((port, self.path), (None, {}))
                if status is None:
                    healthy = any(
                        (PORT[n], PATH_OF[n]) == (port, self.path) for n in PORT
                    )
                    status = 200 if healthy else 404
                body = json.dumps(
                    {"status": "healthy" if status == 200 else "unhealthy"}
                ).encode()
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.closed_port = probe.getsockname()[1]
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.state = tmp_path / "state"
        self.state.mkdir()
        self.env_file = tmp_path / "stack.env"
        self.env_file.write_text(f"REDIS_PASSWORD={REDIS_PASSWORD}\n")

    def answer(self, service, status, path=None, **headers):
        self.answers[(PORT[service], path or PATH_OF[service])] = (status, headers)

    def stub_docker(self):
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(docker.stat().st_mode | stat.S_IEXEC)

    def env(self, **extra):
        # First match wins: the services that are down go to a closed port,
        # everything else to the stub.
        lines = [
            f'connect-to = "localhost:{PORT[name]}:127.0.0.1:{self.closed_port}"'
            for name in sorted(self.down)
        ]
        lines.append(f'connect-to = "::127.0.0.1:{self.port}"')
        (self.tmp / ".curlrc").write_text("\n".join(lines) + "\n")
        env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "CURL_HOME": str(self.tmp),
            "FAKE_STATE": str(self.state),
            # Never the repository's own .env: the Redis check reads the
            # password from the file this names.
            "ENV_FILE": str(self.env_file),
        }
        env.update(extra)
        return env

    def run(self, *command, **extra):
        return subprocess.run(
            list(command),
            env=self.env(**extra),
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def services(self, **extra):
        return self.run("bash", str(HEALTH), "services", **extra)

    def docker_log(self):
        log = self.state / "docker.log"
        return log.read_text() if log.exists() else ""

    def close(self):
        self.server.shutdown()
        self.server.server_close()


FAKE_DOCKER = r"""#!/usr/bin/env bash
# Stub for the docker calls of comprehensive_health_check.sh.
echo "$*" >> "$FAKE_STATE/docker.log"
case " $* " in
  *" compose version "*) exit 0 ;;
  *" pg_isready "*) exit "${FAKE_PG_RC:-0}" ;;
  *"SELECT datname FROM pg_database"*)
    printf '%s\n' ${FAKE_DATABASES-postgres identity data guardian} ;;
  *" redis-cli ping "*)
    # A Redis with a password. The client's is in REDISCLI_AUTH, which
    # docker hands on only when the command names it with -e.
    if [ -n "${FAKE_REDIS_REPLY:-}" ]; then
      echo "$FAKE_REDIS_REPLY"
    elif [[ " $* " != *" -e REDISCLI_AUTH "* ]] || [ -z "${REDISCLI_AUTH:-}" ]; then
      echo "NOAUTH Authentication required."
    elif [ "$REDISCLI_AUTH" = "${FAKE_REDIS_PASSWORD:-made-up-redis-password}" ]; then
      echo "PONG"
    else
      echo "AUTH failed: WRONGPASS invalid username-password pair or user is disabled."
      echo "NOAUTH Authentication required."
    fi ;;
  *" logs "*" gateway "*) echo "${FAKE_GATEWAY_LOG:-}" ;;
esac
exit 0
"""


@pytest.fixture
def stub(tmp_path):
    s = Stub(tmp_path)
    yield s
    s.close()


# --- the probe ---------------------------------------------------------------


def test_a_stack_that_answers_200_everywhere_is_healthy(stub):
    result = stub.services()
    assert result.returncode == 0, result.stdout + result.stderr
    for name in DEFAULT_STACK:
        assert re.search(rf"OK +{name} \(HTTP 200\)", result.stdout), name
    assert "All services are healthy" in result.stdout
    # Each service was asked for its own URL, guardian with the slash.
    for name in DEFAULT_STACK:
        assert (PORT[name], PATH_OF[name]) in stub.requests
    assert (8013, "/health") not in stub.requests


def test_guardian_301_on_health_and_503_on_its_real_route_is_unhealthy(stub):
    """The acceptance test of #656."""
    stub.answer("guardian", 301, path="/health", Location="/health/")
    stub.answer("guardian", 503)
    result = stub.services()
    assert result.returncode != 0
    assert (
        "FAIL  guardian: HTTP 503 from http://localhost:8013/health/" in result.stdout
    )
    assert "OK    guardian" not in result.stdout
    assert "1 service(s) unhealthy" in result.stdout
    # The others are still reported healthy: one failure does not hide them.
    assert re.search(r"OK +identity \(HTTP 200\)", result.stdout)


def test_a_redirect_is_not_followed_and_is_not_healthy(stub):
    """A health URL that redirects to a page answering 200."""
    stub.answer("guardian", 301, Location="/landing")
    stub.answer("guardian", 200, path="/landing")
    result = stub.services()
    assert result.returncode != 0
    assert "FAIL  guardian: HTTP 301" in result.stdout
    assert (8013, "/landing") not in stub.requests


@pytest.mark.parametrize("status", [204, 299])
def test_any_2xx_is_healthy(stub, status):
    stub.answer("identity", status)
    result = stub.services()
    assert result.returncode == 0, result.stdout
    assert re.search(rf"OK +identity \(HTTP {status}\)", result.stdout)


@pytest.mark.parametrize("status", [302, 401, 403, 404, 500, 502, 503])
@pytest.mark.parametrize("service", ["identity", "dashboard", "gateway"])
def test_an_error_status_is_unhealthy_whatever_the_body_says(stub, service, status):
    stub.answer(service, status)
    result = stub.services()
    assert result.returncode != 0
    assert f"FAIL  {service}: HTTP {status}" in result.stdout


def test_no_answer_is_unhealthy(stub):
    stub.down.add("data")
    result = stub.services()
    assert result.returncode != 0
    assert "FAIL  data: no answer from http://localhost:8002/health" in result.stdout


def test_a_profile_service_that_is_not_running_is_skipped_and_named(stub):
    result = stub.services()
    assert result.returncode == 0
    for name, profile in PROFILE_SERVICES.items():
        assert f"SKIP  {name}: not running (profile '{profile}'" in result.stdout


def test_a_profile_named_in_compose_profiles_is_required(stub):
    result = stub.services(COMPOSE_PROFILES="backup,automations")
    assert result.returncode != 0
    assert "FAIL  automations: no answer" in result.stdout
    assert "SKIP  prometheus" in result.stdout


def test_a_profile_service_that_answers_is_held_to_the_same_rule(stub):
    stub.down.discard("prometheus")
    assert stub.services().returncode == 0
    stub.answer("prometheus", 503)
    result = stub.services()
    assert result.returncode != 0
    assert "FAIL  prometheus: HTTP 503" in result.stdout


# --- make health -------------------------------------------------------------


def test_make_health_exits_zero_on_a_healthy_stack(stub):
    stub.stub_docker()
    result = stub.run("make", "health")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Everything checked is healthy" in result.stdout


def test_make_health_fails_when_a_service_is_unhealthy(stub):
    """It printed the failure and exited 0."""
    stub.stub_docker()
    stub.answer("guardian", 503)
    result = stub.run("make", "health")
    assert result.returncode != 0
    assert "FAIL  guardian: HTTP 503" in result.stdout
    assert "1 check(s) failed" in result.stdout


@pytest.mark.parametrize(
    "extra, message",
    [
        ({"FAKE_PG_RC": "1"}, "PostgreSQL is not accepting connections"),
        ({"FAKE_DATABASES": "postgres identity data"}, "no 'guardian' database"),
        ({"FAKE_REDIS_REPLY": "Could not connect to Redis"}, "Redis does not answer"),
    ],
    ids=["postgres-down", "database-missing", "redis-down"],
)
def test_make_health_fails_when_a_database_check_fails(stub, extra, message):
    stub.stub_docker()
    result = stub.run("make", "health", **extra)
    assert result.returncode != 0
    assert message in result.stdout


def test_redis_is_healthy_when_it_answers_pong_to_the_stacks_password(stub):
    stub.stub_docker()
    result = stub.run("bash", str(HEALTH), "databases")
    assert result.returncode == 0, result.stdout
    assert "Redis answers PONG to the stack's password" in result.stdout
    # By name, through the environment: the password is in no argument.
    ping = [line for line in stub.docker_log().splitlines() if "redis-cli ping" in line]
    assert ping == ["compose exec -T -e REDISCLI_AUTH wildbox-redis redis-cli ping"]
    assert REDIS_PASSWORD not in stub.docker_log() + result.stdout + result.stderr


@pytest.mark.parametrize(
    "extra, message",
    [
        # #740: this was "Redis answers", and the check passed.
        ({"FAKE_REDIS_REPLY": "NOAUTH Authentication required."}, "Redis refuses"),
        ({"FAKE_REDIS_PASSWORD": "what-the-server-really-holds"}, "Redis refuses"),
        ({"FAKE_REDIS_REPLY": "LOADING Redis is loading the dataset"}, "does not answer"),
        ({"FAKE_REDIS_REPLY": "PONG and something else"}, "does not answer"),
    ],
    ids=["noauth", "another-password", "loading", "not-exactly-pong"],
)
def test_redis_is_unhealthy_unless_the_reply_is_pong(stub, extra, message):
    stub.stub_docker()
    result = stub.run("bash", str(HEALTH), "databases", **extra)
    assert result.returncode != 0, result.stdout
    assert message in result.stdout
    assert "Redis answers" not in result.stdout
    assert REDIS_PASSWORD not in stub.docker_log() + result.stdout + result.stderr
    # And `make health` as a whole fails with it.
    assert stub.run("make", "health", **extra).returncode != 0


def test_redis_cannot_be_called_healthy_without_a_password_to_check_with(stub):
    stub.stub_docker()
    stub.env_file.write_text("POSTGRES_PASSWORD=made-up\n")
    result = stub.run("bash", str(HEALTH), "databases")
    assert result.returncode != 0
    assert "no REDIS_PASSWORD" in result.stdout
    assert "redis-cli" not in stub.docker_log()


def test_the_redis_password_can_come_from_the_environment(stub):
    stub.stub_docker()
    stub.env_file.write_text("")
    result = stub.run("bash", str(HEALTH), "databases", REDIS_PASSWORD=REDIS_PASSWORD)
    assert result.returncode == 0, result.stdout
    assert REDIS_PASSWORD not in stub.docker_log()


def test_the_check_only_reads_and_repairs_run_on_request(stub):
    """It created a database and restarted the gateway on every run."""
    stub.stub_docker()
    broken = {
        "FAKE_DATABASES": "postgres identity guardian",
        "FAKE_GATEWAY_LOG": "host not found in upstream",
    }
    result = stub.run("make", "health", **broken)
    assert result.returncode != 0
    log = stub.docker_log()
    assert "createdb" not in log and "restart" not in log

    result = stub.run("bash", str(HEALTH), "fix", **broken)
    log = stub.docker_log()
    assert "createdb" in log
    assert "restart gateway" in log


# --- wait-for-services.sh ----------------------------------------------------


def _wait(stub, **extra):
    return stub.run("bash", str(WAIT), MAX_WAIT="2", POLL_INTERVAL="1", **extra)


def test_wait_for_services_finds_guardian_where_it_listens(stub):
    """Its default was port 8003 and /health."""
    result = _wait(stub)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "guardian\x1b[0m is healthy" in result.stdout
    assert (8013, "/health/") in stub.requests
    assert not [request for request in stub.requests if request[0] == 8003]


def test_wait_for_services_does_not_take_a_redirect_for_health(stub):
    stub.answer("guardian", 301, Location="/landing")
    stub.answer("guardian", 200, path="/landing")
    result = _wait(stub)
    assert result.returncode == 0
    assert "guardian\x1b[0m did not become healthy" in result.stdout


def test_wait_for_services_fails_on_a_critical_service(stub):
    stub.answer("identity", 503)
    result = _wait(stub)
    assert result.returncode == 1
    assert "identity\x1b[0m failed to become healthy" in result.stdout


def test_wait_for_services_still_takes_its_list_from_the_environment(stub):
    """As chaos-and-load.yml calls it."""
    result = _wait(
        stub,
        SERVICES="gateway:localhost:80:/health data:localhost:8002:/health",
        OPTIONAL_SERVICES="",
    )
    assert result.returncode == 0, result.stdout
    assert sorted(set(stub.requests)) == [(80, "/health"), (8002, "/health")]


# --- the table is the stack --------------------------------------------------


def _compose():
    return yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())["services"]


def _published_ports(service):
    ports = set()
    for entry in service.get("ports") or []:
        # "127.0.0.1:8001:8001", "80:80"
        ports.add(int(str(entry).split(":")[-2]))
    return ports


def test_every_service_with_a_published_port_is_in_the_table():
    """The other half of the acceptance test of #656."""
    published = {
        name: _published_ports(service)
        for name, service in _compose().items()
        if service.get("ports")
    }
    assert set(published) == set(PORT)
    for name, ports in published.items():
        assert PORT[name] in ports, f"{name}: {PORT[name]} is not one of {ports}"


def test_the_profiles_in_the_table_are_the_ones_in_the_compose_file():
    services = _compose()
    for name, _, profile in ENDPOINTS:
        declared = services[name].get("profiles") or []
        assert ([profile] if profile else []) == declared, name


def test_the_table_uses_the_url_each_container_healthcheck_uses():
    services = _compose()
    for name, url, _ in ENDPOINTS:
        test = (services[name].get("healthcheck") or {}).get("test")
        # No exemption: prometheus, the one service that had no healthcheck,
        # has one since #658.
        assert test, f"{name} has no healthcheck to compare"
        command = " ".join(test)
        urls = re.findall(r"http://localhost[^\s'\",)]*", command)
        assert urls == [url], f"{name}: healthcheck probes {urls}, the table {url}"


def test_the_table_matches_the_ports_guide():
    guide = (REPO_ROOT / "docs" / "guides" / "ports.md").read_text()
    documented = {}
    for line in guide.splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) < 7 or not cells[1].startswith("`"):
            continue
        urls = re.findall(r"`(http://localhost[^`]*)`", cells[5])
        if urls:
            documented[cells[1].strip("`")] = urls[0]
    assert documented == {name: url for name, url, _ in ENDPOINTS}


def test_no_script_probes_guardian_anywhere_else():
    """/health without the slash, or the port it never listened on."""
    offenders = []
    for path in [*REPO_ROOT.glob("scripts/**/*.sh"), *REPO_ROOT.glob("tests/*.sh")]:
        text = path.read_text(errors="ignore")
        if re.search(r"8013/health(?!/)", text) or re.search(
            r"guardian\S*:8003\b", text
        ):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_the_table_names_the_scripts_that_source_it_and_no_other():
    """The header of the table says who sources it. It went on naming
    system_monitor.sh after #706 removed it; tests/test_all_pages.sh, the
    other script it named, called the backends without the gateway's
    identity headers and was run by nothing (#665)."""
    header = TABLE.read_text().split("\n\n", 1)[0]
    named = set(re.findall(r"\b(?:scripts|tests)/[\w./-]+\.sh\b", header))
    sourcing = set()
    for path in [*REPO_ROOT.glob("scripts/**/*.sh"), *REPO_ROOT.glob("tests/**/*.sh")]:
        if path == TABLE:
            continue
        if re.search(
            r"^\s*(?:\.|source)\s.*health_endpoints\.sh", path.read_text(), re.M
        ):
            sourcing.add(str(path.relative_to(REPO_ROOT)))
    assert sourcing, "no script sources the table: the search is wrong"
    assert named == sourcing
    assert not (REPO_ROOT / "tests" / "test_all_pages.sh").exists()


# --- the API-doc generators --------------------------------------------------


def test_the_stale_generators_are_gone_and_nothing_points_at_them():
    assert not list((REPO_ROOT / "scripts").glob("generate-api-docs*"))
    tracked = subprocess.run(
        ["git", "grep", "-l", "-e", "generate-api-docs", "-e", "redoc@next"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    ).stdout.split()
    allowed = ("CHANGELOG.md", "docs/archive/", "docs/api/README.md", "tests/scripts/")
    assert [path for path in tracked if not path.startswith(allowed)] == []


@pytest.mark.parametrize("service", ["agents", "responder"])
def test_the_exported_schema_pages_are_redirects_to_the_references(service):
    page = (REPO_ROOT / "docs" / "api" / f"{service}-api.html").read_text()
    target = f"/api/{service}/endpoints/"
    assert f'<meta http-equiv="refresh" content="0; url={target}">' in page
    assert 'content="noindex, follow"' in page
    # No schema, no viewer, nothing from the removed vendor directory.
    assert "<script" not in page and "/vendor/" not in page
    assert len(page) < 2000
    assert (REPO_ROOT / "docs" / "api" / service / "endpoints.md").is_file()


def test_the_site_no_longer_offers_the_exported_schema_pages():
    for name in ("docs.html", "api-reference.html", "sitemap.xml", "api/README.md"):
        text = (REPO_ROOT / "docs" / name).read_text()
        assert 'href="/api/agents-api.html"' not in text, name
        assert 'href="/api/responder-api.html"' not in text, name
        assert "(agents-api.html)" not in text and "(responder-api.html)" not in text
        assert "wildbox.io/api/agents-api.html" not in text, name
    assert not (REPO_ROOT / "docs" / "api" / "vendor").exists()
