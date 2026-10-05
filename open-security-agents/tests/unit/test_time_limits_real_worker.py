"""The time limits, hit for real (#727).

A Celery worker, the API and a Redis, each a real process: the API is
``uvicorn app.main:app``, the worker is app/worker.py with the agent alone
replaced (tests/unit/standin_worker.py: no model is called), and Redis is a
throwaway container. An analysis is submitted over HTTP, as the gateway
would forward it, and then:

- runs past the soft time limit, and is interrupted and recorded by the
  task itself, before the hard one;
- ignores the soft limit, and is killed at the hard one;
- loses its process to SIGKILL.

On main the last two read ``failed`` with the generic reason, with no code
recorded and ``failed_today`` unchanged. tests/unit/test_time_limits.py
covers the same hooks without a worker, and the one case that cannot be
waited for here: a task whose whole worker is gone, which the API reports
after the hard limit of ten minutes.

Needs Docker for the Redis container. Skipped where there is none; CI sets
WILDBOX_REQUIRE_DOCKER_TESTS=1 so that it runs there.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest
import redis as redis_lib

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from app import failures  # noqa: E402

REDIS_IMAGE = "redis:7-alpine"  # the image docker-compose.yml runs
SOFT_LIMIT_SECONDS = 2
HARD_LIMIT_SECONDS = 6
# Long enough for a slow runner to start the worker; a task that is never
# recorded fails the test at this deadline instead of hanging it.
DEADLINE_SECONDS = 120
SECRET = "gateway-secret-for-the-real-worker-test"
HEADERS = {
    "X-Wildbox-User-ID": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "X-Wildbox-Team-ID": "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b",
    "X-Wildbox-Role": "member",
    "X-Gateway-Secret": SECRET,
}


def _docker_available():
    if not shutil.which("docker"):
        return False
    return (
        subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode
        == 0
    )


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _wait_for(what, check, seconds=DEADLINE_SECONDS, detail=lambda: ""):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = check()
        except (httpx.HTTPError, redis_lib.RedisError, OSError):
            value = None
        if value:
            return value
        time.sleep(0.25)
    pytest.fail(f"{what} did not happen within {seconds} s\n{detail()}")


class Stack:
    """Redis in a container, the worker and the API as processes."""

    def __init__(self, root):
        self.root = root
        self.container = f"wbtest727-{uuid.uuid4().hex[:8]}"
        self.processes = []
        self.logs = {}

    def start(self):
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                self.container,
                "-p",
                "127.0.0.1::6379",
                REDIS_IMAGE,
            ],
            check=True,
            capture_output=True,
            timeout=300,
        )
        published = subprocess.run(
            ["docker", "port", self.container, "6379/tcp"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.split()[0]
        url = f"redis://{published}/0"
        self.redis = redis_lib.from_url(url)
        _wait_for("Redis answering", self.redis.ping)

        env = {
            name: os.environ[name]
            for name in ("PATH", "HOME", "LANG", "TMPDIR")
            if name in os.environ
        }
        env.update(
            PYTHONPATH=os.pathsep.join([str(SERVICE_ROOT), str(Path(__file__).parent)]),
            REDIS_URL=url,
            CELERY_BROKER_URL=url,
            CELERY_RESULT_BACKEND=url,
            GATEWAY_INTERNAL_SECRET=SECRET,
            # Never sent anywhere: the stand-in agent calls no model. Set so
            # that the task does not fail at once as "not configured".
            ANTHROPIC_API_KEY="unit-tests-do-not-call-the-model",
            ANALYZE_RATE_LIMIT="100/minute",
        )
        self.spawn(
            "worker",
            env,
            "-m",
            "celery",
            "-A",
            "standin_worker",
            "worker",
            "--loglevel=warning",
            "--concurrency=3",
            f"--soft-time-limit={SOFT_LIMIT_SECONDS}",
            f"--time-limit={HARD_LIMIT_SECONDS}",
            "-n",
            f"{self.container}@%h",
        )
        port = _free_port()
        self.spawn(
            "api",
            env,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        )
        self.api = httpx.Client(
            base_url=f"http://127.0.0.1:{port}", headers=HEADERS, timeout=30
        )
        _wait_for(
            "the API answering",
            lambda: self.api.get("/health").status_code == 200,
            detail=lambda: self.log("api"),
        )

    def spawn(self, name, env, *args):
        self.logs[name] = self.root / f"{name}.log"
        with open(self.logs[name], "w") as log:
            self.processes.append(
                subprocess.Popen(
                    [sys.executable, *args],
                    cwd=SERVICE_ROOT,
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
            )

    def log(self, name):
        return f"--- {name} log\n{self.logs[name].read_text()[-4000:]}"

    def stop(self):
        for process in self.processes:
            process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
        subprocess.run(
            ["docker", "rm", "-f", self.container], capture_output=True, timeout=60
        )

    # --- what the tests ask ---

    def submit(self, behavior):
        response = self.api.post(
            "/v1/analyze",
            json={"ioc": {"type": "domain", "value": f"{behavior}.example.com"}},
        )
        assert response.status_code == 202, response.text
        return response.json()["task_id"]

    def read(self, task_id):
        response = self.api.get(f"/v1/analyze/{task_id}")
        assert response.status_code == 200, response.text
        return response.json()

    def celery_meta(self, task_id):
        """What Celery stored for the task, read from Redis, not the API."""
        celery_id = self.redis.get(f"task:{task_id}:celery_id").decode()
        raw = self.redis.get(f"celery-task-meta-{celery_id}")
        return json.loads(raw) if raw else {}

    def failed_in_celery(self, task_id):
        """Wait for Celery to mark the task failed; the exception's type."""
        return _wait_for(
            f"task {task_id} failing",
            lambda: (
                meta["result"]["exc_type"]
                if (meta := self.celery_meta(task_id)).get("status") == "FAILURE"
                else None
            ),
            detail=lambda: self.log("worker"),
        )

    def recorded(self, task_id):
        """The failure code Redis holds for the task, or None."""
        code = self.redis.get(f"task:{task_id}:error")
        return code.decode() if code is not None else None

    def failed_today(self):
        """Every stats:failed:<date> key: one, unless midnight UTC passes."""
        return sum(
            int(self.redis.get(key)) for key in self.redis.keys("stats:failed:*")
        )


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    if not _docker_available():
        if os.environ.get("WILDBOX_REQUIRE_DOCKER_TESTS") == "1":
            pytest.fail("docker is required for these tests and is not available")
        pytest.skip("docker is not available")
    stack = Stack(tmp_path_factory.mktemp("stack727"))
    try:
        stack.start()
        yield stack
    finally:
        stack.stop()


BEHAVIORS = ("soft-limit", "hard-limit", "lost-process")


class Ended:
    """The three analyses once Celery has marked them failed, and what the
    worker had recorded for them by then, before the API read any of them:
    reading a failed task records it too (the last tests of this module)."""

    def __init__(self, stack):
        assert stack.failed_today() == 0
        self.ids = {behavior: stack.submit(behavior) for behavior in BEHAVIORS}
        self.exceptions = {
            behavior: stack.failed_in_celery(task_id)
            for behavior, task_id in self.ids.items()
        }
        # Celery stores the failure, then tells the worker's hook: give the
        # hook a moment, without failing here if it records nothing.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and stack.failed_today() < len(BEHAVIORS):
            time.sleep(0.25)
        self.codes = {
            behavior: stack.recorded(task_id) for behavior, task_id in self.ids.items()
        }
        self.counted = stack.failed_today()


@pytest.fixture(scope="module")
def ended(stack):
    return Ended(stack)


def test_the_soft_limit_interrupts_the_task_which_records_it(stack, ended):
    # Raised in the task, not killed: what Celery stored is the soft limit.
    assert ended.exceptions["soft-limit"] == "SoftTimeLimitExceeded"
    assert ended.codes["soft-limit"] == failures.TIMED_OUT

    body = stack.read(ended.ids["soft-limit"])
    assert body["status"] == "failed"
    assert body["error"] == failures.REASONS[failures.TIMED_OUT]


def test_a_task_killed_at_the_hard_limit_is_recorded_by_the_worker(stack, ended):
    assert ended.exceptions["hard-limit"] == "TimeLimitExceeded"
    assert ended.codes["hard-limit"] == failures.TIMED_OUT

    body = stack.read(ended.ids["hard-limit"])
    assert body["status"] == "failed"
    assert body["error"] == failures.REASONS[failures.TIMED_OUT]
    assert body["completed_at"]


def test_a_task_whose_process_was_killed_is_recorded_by_the_worker(stack, ended):
    assert ended.exceptions["lost-process"] == "WorkerLostError"
    assert ended.codes["lost-process"] == failures.INTERRUPTED

    body = stack.read(ended.ids["lost-process"])
    assert body["status"] == "failed"
    assert body["error"] == failures.REASONS[failures.INTERRUPTED]


def test_each_of_them_is_counted_once_however_often_it_is_read(stack, ended):
    assert ended.counted == 3, "counted before anything read the tasks"

    for task_id in ended.ids.values():
        for _ in range(3):
            assert stack.read(task_id)["status"] == "failed"

    assert stack.failed_today() == 3
    stats = stack.api.get("/stats")
    assert stats.status_code == 200, stats.text
    assert stats.json()["failed_today"] == 3


@pytest.mark.parametrize(
    "behavior, code",
    [("hard-limit", failures.TIMED_OUT), ("lost-process", failures.INTERRUPTED)],
)
def test_the_api_records_from_celerys_state_what_the_worker_could_not(
    stack, ended, behavior, code
):
    """The worker's record removed, as if its write had failed: the API
    reads the exception Celery stored, records its code, counts it once."""
    task_id = ended.ids[behavior]
    before = stack.failed_today()
    stack.redis.delete(f"task:{task_id}:error", f"task:{task_id}:status")

    for _ in range(3):
        body = stack.read(task_id)
        assert body["status"] == "failed"
        assert body["error"] == failures.REASONS[code]

    assert stack.recorded(task_id) == code
    assert stack.failed_today() == before + 1
