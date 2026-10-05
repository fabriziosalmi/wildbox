"""The production worker with a stand-in for the agent.

``celery -A standin_worker worker`` runs app/worker.py as it is: the task,
its time limits, what it records and the task_failure hook are the
production ones. Only the agent is replaced, by one that calls no model and
ends the way the indicator's first label asks. It is what
test_time_limits_real_worker.py starts; nothing else imports it.
"""

import asyncio
import os
import signal
import time

from app import worker
from app.worker import celery_app  # noqa: F401  (what `celery -A` loads)

SOFT_LIMIT = "soft-limit"
HARD_LIMIT = "hard-limit"
LOST_PROCESS = "lost-process"


class StandInAgent:
    async def analyze_ioc(self, ioc):
        behavior = ioc["value"].split(".")[0]
        if behavior == SOFT_LIMIT:
            # Still waiting, as for a model's answer, when the soft limit
            # is reached: Celery raises SoftTimeLimitExceeded in the task.
            await asyncio.sleep(3600)
        if behavior == HARD_LIMIT:
            # Deaf to the soft limit, which Celery delivers as SIGUSR1, and
            # blocked: only the hard limit ends it, by killing this process.
            signal.signal(signal.SIGUSR1, signal.SIG_IGN)
            time.sleep(3600)
        if behavior == LOST_PROCESS:
            # What the kernel's out-of-memory killer does to a process.
            os.kill(os.getpid(), signal.SIGKILL)
        raise AssertionError(f"no stand-in behavior for {ioc['value']!r}")


worker.get_threat_enrichment_agent = StandInAgent
