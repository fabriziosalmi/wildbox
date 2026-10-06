"""One request for every route of the cspm application, and a stock of scans.

``GET /api/v1/checks`` and ``GET /api/v1/scans/{id}/compliance`` answered 500
for every caller (#766). Both built their own response model wrongly, and no
test called either route: the endpoints were tested as functions, one at a
time, and these two were not among them.

Three test files walk the routes of the application with what is here:

- ``test_route_answers.py``: the answer of every route validates against the
  model the route declares;
- ``test_dependency_unavailable.py``: every route that needs Redis answers
  503 when Redis cannot be reached;
- ``test_cancel_scan.py``: what ``DELETE`` does to a scan in each state.

They take the routes from the application and look the request up in
``REQUESTS``, so a route added to ``app.main`` fails them until it has a
request here.

The scans are made the way the service makes them: started through the API,
and completed or failed by the worker's own task, run in this process, with
the real runner and the real report. Only the cloud is missing: the checks a
scan runs have their ``execute`` replaced, and each result is still made by
the check's own ``create_result``, from its real metadata.
"""

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Tuple

from app import config, main, worker
from app.checks.framework import CheckStatus, CloudProvider
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

SECRET = "s" * 40
TEAM = "9c858901-8a57-4791-81fe-4c455b099bc9"
OTHER_TEAM = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
HEADERS = {
    "X-Wildbox-User-ID": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "X-Wildbox-Team-ID": TEAM,
    "X-Wildbox-Role": "member",
    "X-Gateway-Secret": SECRET,
    "X-Wildbox-Auth-Type": "api_key",
}
OTHER_TEAM_HEADERS = {
    **HEADERS,
    "X-Wildbox-User-ID": "6fa459ea-ee8a-4ca4-894e-db77e160355e",
    "X-Wildbox-Team-ID": OTHER_TEAM,
}

ACCOUNT = "123456789012"
REGION = "eu-west-1"

# A scan id that is well formed and names no scan.
NO_SUCH_SCAN = "00000000-0000-4000-8000-000000000000"


def scan_request(account_id: str = ACCOUNT, **extra: Any) -> Dict[str, Any]:
    """The body of POST /api/v1/scans for one AWS account."""
    return {
        "provider": "aws",
        "account_id": account_id,
        "credentials": {
            "auth_method": "access_key",
            "access_key_id": "AKIAFAKEFAKEFAKEFAKE",
            "secret_access_key": "fake-secret-for-tests-only",
        },
        "regions": [REGION],
        **extra,
    }


@dataclass
class Scans:
    """The id of one scan in each state a scan can be read in."""

    queued: str
    running: str
    completed: str
    failed: str


SAME_ID_EVERYWHERE = Scans(NO_SUCH_SCAN, NO_SUCH_SCAN, NO_SUCH_SCAN, NO_SUCH_SCAN)

Route = Tuple[str, str]

# (method, path as the application declares it) -> the arguments of the
# request, given the stock of scans. "path" fills the path's parameters.
REQUESTS: Dict[Route, Callable[[Scans], Dict[str, Any]]] = {
    ("GET", "/metrics"): lambda scans: {},
    ("GET", "/health/live"): lambda scans: {},
    ("GET", "/health"): lambda scans: {},
    ("POST", "/api/v1/scans"): lambda scans: {"json": scan_request("210987654321")},
    ("GET", "/api/v1/scans/{scan_id}"): lambda scans: {
        "path": {"scan_id": scans.completed}
    },
    ("GET", "/api/v1/scans/{scan_id}/report"): lambda scans: {
        "path": {"scan_id": scans.completed}
    },
    ("GET", "/api/v1/scans/{scan_id}/compliance"): lambda scans: {
        "path": {"scan_id": scans.completed}
    },
    ("DELETE", "/api/v1/scans/{scan_id}"): lambda scans: {
        "path": {"scan_id": scans.running}
    },
    ("POST", "/api/v1/batch/scans"): lambda scans: {
        "json": {"scans": [scan_request("111111111111"), scan_request("222222222222")]}
    },
    ("GET", "/api/v1/providers"): lambda scans: {},
    ("GET", "/api/v1/checks"): lambda scans: {},
    ("GET", "/api/v1/dashboard/summary"): lambda scans: {},
    ("GET", "/api/v1/compliance/summary"): lambda scans: {},
    ("GET", "/api/v1/compliance/findings"): lambda scans: {},
}


def application_routes() -> List[APIRoute]:
    """Every route the application serves, one entry per method."""
    return [route for route in main.app.routes if isinstance(route, APIRoute)]


def route_keys() -> List[Route]:
    """(method, path) of every route of the application, sorted."""
    return sorted(
        (method, route.path)
        for route in application_routes()
        for method in route.methods
    )


def route_named(method: str, path: str) -> APIRoute:
    for route in application_routes():
        if route.path == path and method in route.methods:
            return route
    raise LookupError(f"no route {method} {path}")


def send(client: TestClient, method: str, path: str, scans: Scans, headers=None):
    """Send the request ``REQUESTS`` holds for a route; return the response."""
    arguments = dict(REQUESTS[(method, path)](scans))
    url = path.format(**arguments.pop("path", {}))
    return client.request(
        method, url, headers=HEADERS if headers is None else headers, **arguments
    )


# --- Celery, without a broker --------------------------------------------------


class QueuedTasks:
    """Stands in for run_cspm_scan_task: records what would be queued."""

    def __init__(self):
        self.calls = []

    def apply_async(self, args, task_id):
        self.calls.append((task_id, args[0]))

    def config_of(self, scan_id: str) -> Dict[str, Any]:
        return next(queued for task_id, queued in self.calls if task_id == scan_id)


class Control:
    """Stands in for celery_app.control: one worker answers, revocations are kept."""

    def __init__(self):
        self.revoked = []
        self.workers = {"celery@worker-1": []}
        self.inspections = 0

    def revoke(self, task_id, terminate=False):
        self.revoked.append((task_id, terminate))

    def inspect(self):
        self.inspections += 1
        return SimpleNamespace(active=lambda: self.workers)


class Celery:
    """Stands in for celery_app: task states as the result backend would hold them."""

    def __init__(self):
        self.control = Control()
        self.states = {}

    def AsyncResult(self, task_id):  # noqa: N802 - Celery's name
        state, info = self.states.get(task_id, ("PENDING", None))
        return SimpleNamespace(status=state, info=info)


# --- The stock of scans --------------------------------------------------------


@dataclass
class World:
    client: TestClient
    scans: Scans
    celery: Celery
    queue: QueuedTasks
    redis: Any
    # The three real checks the completed scan ran.
    checks: List[Any]


def _canned(check, results):
    """An ``execute`` that answers ``results`` through the check's create_result."""

    async def execute(session, region=None):
        return [
            check.create_result(
                resource_id=resource_id,
                resource_type="Resource",
                status=status,
                message=f"{resource_id} {status.value}",
                region=region,
            )
            for resource_id, status in results
        ]

    return execute


def _raising(error):
    async def execute(session, region=None):
        raise error

    return execute


def start_scan(client: TestClient, headers=None, **request) -> str:
    """Start a scan through the API; return its id."""
    response = client.post(
        "/api/v1/scans",
        json=scan_request(**request),
        headers=HEADERS if headers is None else headers,
    )
    assert response.status_code == 202, response.text
    return response.json()["scan_id"]


def run_worker(world_queue: QueuedTasks, scan_id: str):
    """Run the worker's task for a queued scan, in this process.

    Returns Celery's result of the run: its state, and what the task
    returned or raised.
    """
    return worker.run_cspm_scan_task.apply(
        args=[world_queue.config_of(scan_id)], task_id=scan_id
    )


def build_world(monkeypatch, fake_redis) -> World:
    """The API and the worker on one fake Redis, with a scan in each state."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(config.settings, "cspm_report_retention_days", 90)
    celery = Celery()
    queue = QueuedTasks()
    monkeypatch.setattr(main, "redis_client", fake_redis)
    monkeypatch.setattr(main, "celery_app", celery)
    monkeypatch.setattr(main, "run_cspm_scan_task", queue)
    monkeypatch.setattr(worker, "redis_client", fake_redis)
    monkeypatch.setattr(worker.run_cspm_scan_task, "update_state", lambda **_: None)

    sessions = {"usable": True}

    def create_session(provider, credentials):
        if not sessions["usable"]:
            raise ValueError("no session can be opened with these credentials")
        return object()

    monkeypatch.setattr(worker, "_create_cloud_session", create_session)

    # Three of the real checks, answering without a cloud: verdicts both
    # ways, a result the check itself gives no verdict on, and one check that
    # raises, which the runner records as an error.
    passing, failing, erroring = main.check_runner.loaded_checks[CloudProvider.AWS][:3]
    monkeypatch.setattr(
        passing,
        "execute",
        _canned(
            passing,
            [
                ("res-1", CheckStatus.PASSED),
                ("res-2", CheckStatus.FAILED),
                ("res-4", CheckStatus.SKIPPED),
            ],
        ),
    )
    monkeypatch.setattr(
        failing, "execute", _canned(failing, [("res-3", CheckStatus.FAILED)])
    )
    monkeypatch.setattr(erroring, "execute", _raising(ValueError("no such API")))
    checks = [passing, failing, erroring]
    check_ids = [check.metadata.check_id for check in checks]

    client = TestClient(main.app, raise_server_exceptions=False)

    completed = start_scan(client, account_name="Production", check_ids=check_ids)
    run_worker(queue, completed)

    failed = start_scan(client, account_id="333333333333")
    sessions["usable"] = False
    run_worker(queue, failed)
    sessions["usable"] = True

    queued = start_scan(client, account_id="444444444444")

    running = start_scan(client, account_id="555555555555")
    celery.states[running] = (
        "PROGRESS",
        {"status": "initializing", "provider": "aws", "account_id": "555555555555"},
    )

    return World(
        client=client,
        scans=Scans(queued=queued, running=running, completed=completed, failed=failed),
        celery=celery,
        queue=queue,
        redis=fake_redis,
        checks=checks,
    )
