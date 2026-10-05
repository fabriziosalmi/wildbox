"""The service's Celery app, for the tests that run a real worker.

``celery -A async_worker_app worker`` starts what ``tools-worker`` starts:
``app.celery_app`` with ``app.tasks``, the task, its retry policy and the
handlers that count how a task ended, all unchanged. Only three things
differ, each named by the test through the environment:

* the worker reads a queue of the test's own, so a Redis that something
  else uses is left alone;
* the counts go to keys of the test's own, for the same reason;
* ``app.tools`` also finds the packages under ``support/tools``, which hold
  ``metrics_probe``, a tool that ends the way the test asks. It is loaded
  by the service's own loader, like any tool.
"""

import os

import app.tools
from app import tasks  # noqa: F401  (registers the task and its handlers)
from app import async_metrics
from app.celery_app import celery_app

app.tools.__path__.append(os.environ["TOOLS_TEST_EXTRA_TOOLS"])
async_metrics.OUTCOMES_KEY = os.environ["TOOLS_TEST_OUTCOMES_KEY"]
async_metrics.CONSUMED_KEY = os.environ["TOOLS_TEST_CONSUMED_KEY"]
celery_app.conf.task_default_queue = os.environ["TOOLS_TEST_QUEUE"]

# What `celery -A async_worker_app` looks for.
celery = celery_app
