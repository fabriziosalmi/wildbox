"""The service's Celery app as real prefork workers, for tests.

``Stack`` starts ``support/async_worker_app.py`` (the service's own app and
task, unchanged) against a Redis server, sends it tasks from a client of its
own, and reads what it left in Redis. Everything it writes is named after one
random run, so a Redis that something else uses is left alone, and several
workers can be started, stopped and killed in one test.
"""

import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

SUPPORT = Path(__file__).resolve().parent
SERVICE_ROOT = SUPPORT.parents[2]
TASK = "app.tasks.execute_tool_async"
PROBE = "metrics_probe"


class Worker:
    """One worker process (its main process and, through it, its children)."""

    def __init__(self, process, node, queue, log_path):
        self.process = process
        self.node = node
        self.queue = queue
        self.log_path = log_path

    def log_since(self, mark=0):
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return text[mark:]

    def alive(self):
        return self.process.poll() is None

    def stop(self):
        """Shut down as `docker stop` does: SIGTERM, then wait."""
        if self.alive():
            self.process.terminate()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.kill()

    def kill(self):
        """Kill the whole worker, main process and children, as `docker kill`
        or the kernel's out-of-memory killer on the container does."""
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.process.wait(timeout=30)


class Stack:
    """Workers, a client to send them tasks, and the counts they write."""

    def __init__(self, redis_url, workdir):
        import redis
        from celery import Celery

        self.redis_url = redis_url
        self.workdir = Path(workdir)
        self.run = uuid.uuid4().hex[:12]
        self.queue = f"wildbox-tools-test-{self.run}"
        self.outcomes_key = f"wildbox:tools:test-{self.run}:async-outcomes"
        self.consumed_key = f"wildbox:tools:test-{self.run}:async-consumed"
        self.redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self.app = Celery(f"client-{self.run}", broker=redis_url, backend=redis_url)
        self.app.conf.update(
            task_serializer="json",
            accept_content=["json"],
            result_serializer="json",
            broker_connection_retry_on_startup=True,
        )
        self.workers = []
        self.queues = [self.queue]
        self.sent = []
        self.worker = None  # the first one started: the one most tests use

    # --- workers ---------------------------------------------------------------

    def new_queue(self):
        """A queue no worker reads until one is started for it."""
        queue = f"{self.queue}-{len(self.queues)}"
        self.queues.append(queue)
        return queue

    def start_worker(self, queue=None, env=None, wait=True):
        queue = queue or self.queue
        number = len(self.workers)
        node = f"probe-{self.run}-{number}@localhost"
        log_path = self.workdir / f"worker-{number}.log"
        with open(log_path, "w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "celery",
                    "-A",
                    "async_worker_app:celery_app",
                    "worker",
                    "--pool=prefork",
                    "--concurrency=1",
                    # Every task in a child of its own: a count kept in a
                    # child would never get past one.
                    "--max-tasks-per-child=1",
                    "--loglevel=info",
                    "--without-gossip",
                    "--without-mingle",
                    "-Q",
                    queue,
                    "-n",
                    node,
                ],
                # Not the service directory: a developer's .env there is not
                # ours to read.
                cwd=str(self.workdir),
                stdout=log,
                stderr=subprocess.STDOUT,
                # A process group of its own, so the whole worker can be killed.
                start_new_session=True,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONPATH": os.pathsep.join([str(SERVICE_ROOT), str(SUPPORT)]),
                    "API_KEY": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                    "REDIS_URL": self.redis_url,
                    "TOOLS_TEST_EXTRA_TOOLS": str(SUPPORT / "tools"),
                    "TOOLS_TEST_OUTCOMES_KEY": self.outcomes_key,
                    "TOOLS_TEST_CONSUMED_KEY": self.consumed_key,
                    "TOOLS_TEST_QUEUE": queue,
                    **(env or {}),
                },
            )
        worker = Worker(process, node, queue, log_path)
        self.workers.append(worker)
        if self.worker is None:
            self.worker = worker
        if wait:
            self.wait_ready(worker)
        return worker

    def wait_ready(self, worker, seconds=90):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            assert worker.alive(), worker.log_since()[-4000:]
            replies = self.app.control.inspect(
                destination=[worker.node], timeout=1
            ).ping()
            if replies and worker.node in replies:
                return
        raise AssertionError(worker.log_since()[-4000:])

    def close(self):
        for worker in self.workers:
            if worker.alive():
                worker.stop()
        keys = [self.outcomes_key, self.consumed_key, *self.queues]
        keys += [f"celery-task-meta-{task_id}" for task_id in self.sent]
        keys += [f"wildbox:tools:task-cancelled:{task_id}" for task_id in self.sent]
        keys += [f"wildbox:tools:task-starts:{task_id}" for task_id in self.sent]
        self.redis.delete(*keys)
        self.app.close()
        self.redis.close()

    # --- tasks -------------------------------------------------------------------

    def send(self, tool=PROBE, input_data=None, user_id=None, queue=None, **options):
        result = self.app.send_task(
            TASK,
            kwargs={
                "tool_name": tool,
                "input_data": input_data or {},
                "user_id": user_id or str(uuid.uuid4()),
            },
            queue=queue or self.queue,
            **options,
        )
        self.sent.append(result.id)
        return result

    def probe(self, behaviour, seconds=0.0, queue=None, **options):
        return self.send(
            input_data={"behaviour": behaviour, "seconds": seconds},
            queue=queue,
            **options,
        )

    def meta(self, result):
        return self.app.backend.get_task_meta(result.id)

    def state(self, result, among, seconds=60):
        """Wait for the task to reach one of ``among``; return its meta."""
        deadline = time.monotonic() + seconds
        meta = self.meta(result)
        while meta["status"] not in among and time.monotonic() < deadline:
            time.sleep(0.1)
            meta = self.meta(result)
        assert meta["status"] in among, (meta, self.log())
        return meta

    # --- what the workers left in Redis ---------------------------------------------

    def outcomes(self):
        """{(tool, outcome): count}, as the workers of this stack counted."""
        return {
            tuple(field.rsplit("|", 1)): int(count)
            for field, count in self.redis.hgetall(self.outcomes_key).items()
        }

    def consumed(self):
        return int(self.redis.get(self.consumed_key) or 0)

    def queued(self, queue=None):
        return self.redis.llen(queue or self.queue)

    def settled(self, before, expected, seconds=30):
        """Wait until the outcome counts grew by exactly ``expected``.

        Then wait a little longer and look again: the count must stay there,
        which is what "counted once" means.
        """

        def grown():
            now = self.outcomes()
            return {
                key: now.get(key, 0) - before.get(key, 0)
                for key in set(now) | set(before)
                if now.get(key, 0) != before.get(key, 0)
            }

        deadline = time.monotonic() + seconds
        while grown() != expected and time.monotonic() < deadline:
            time.sleep(0.1)
        assert grown() == expected, self.log()
        time.sleep(1.0)
        assert grown() == expected, self.log()

    # --- the first worker's log -------------------------------------------------------

    def log(self):
        """The end of the first worker's log, for a failure message."""
        return self.log_since(0)[-4000:]

    def mark(self):
        """Where the first worker's log ends now."""
        return len(self.log_since(0))

    def log_since(self, mark, worker=None):
        return (worker or self.worker).log_since(mark)

    def logged(self, mark, wanted, seconds=30, worker=None):
        """Wait for a worker to log ``wanted`` after ``mark``; return that log.

        The worker writes its log after it stores a task's state, so a line
        about a task can follow the state the test waited for.
        """
        deadline = time.monotonic() + seconds
        text = self.log_since(mark, worker)
        while wanted.lower() not in text.lower() and time.monotonic() < deadline:
            time.sleep(0.1)
            text = self.log_since(mark, worker)
        assert wanted.lower() in text.lower(), text[-4000:]
        return text
