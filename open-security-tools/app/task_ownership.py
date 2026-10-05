"""Who submitted each asynchronous task, so that only they can see it (#567).

Celery's result backend keeps a task's state and result under its id and
nothing else: it does not know who submitted the task, and it reports any id
it has never seen as PENDING. The task endpoints therefore record the owner at
submission, in the same Redis, and answer every later request about the task
from that record:

* ``wildbox:tools:task-owner:<task_id>`` holds the owner (user and team), the
  tool name and the submission time, as JSON;
* ``wildbox:tools:user-tasks:<user_id>`` is a sorted set of the user's task ids,
  scored by submission time, which the list endpoint reads.

A task without an owner record, such as one submitted before this record
existed, belongs to nobody and is not readable. There is no administrator
override: a task's result can carry what a tool found for the caller it acted
for, and operators who need every task have Flower.

A cancellation is recorded here too (#743):

* ``wildbox:tools:task-cancelled:<task_id>`` exists once the task's owner has
  cancelled it.

Celery's own revocation is a broadcast that the workers running at that
moment keep in memory. A pending task with no worker alive, or a worker that
restarts before it takes the task, has nobody holding it: the task ran when a
worker came back, after its owner had been told it was cancelled. The marker
is in Redis, where the queue is, so it is there for as long as the task can
be: the task reads it first when it starts and does not run
(``app.tasks``), and the API reads it to answer ``cancelled`` at once. Only
the owner's ``DELETE`` writes it, after the same ownership check as every
other request about the task.

And how often a task was started (#743):

* ``wildbox:tools:task-starts:<task_id>`` counts the starts of the task.

A task whose worker process dies while it runs is put back on the queue
(``task_acks_late`` with ``task_reject_on_worker_lost``), which is right for
a process that was killed once and wrong for a tool that takes its process
down every time: that task came back without end. Nothing in the message
says how often it was delivered (the Redis transport keeps no such count),
so the task counts its own starts here and gives up after too many that
left no result (``app.tasks``).
"""

import json
import time
from typing import Any, Dict, List, Optional, Set

# How long an owner record lives. Celery keeps a result for an hour after the
# task finishes (result_expires in app/celery_app.py), and a task may wait in
# the queue before it starts; the record must outlive both, or a finished
# task would turn into "not found" for its own owner while the result is still
# there. A day covers any task that starts within the day it was submitted.
OWNER_TTL_SECONDS = 24 * 60 * 60

_OWNER_KEY = "wildbox:tools:task-owner:{task_id}"
_USER_INDEX_KEY = "wildbox:tools:user-tasks:{user_id}"
_CANCELLED_KEY = "wildbox:tools:task-cancelled:{task_id}"
_STARTS_KEY = "wildbox:tools:task-starts:{task_id}"


class TaskOwnershipUnavailable(RuntimeError):
    """The owner records cannot be read or written (no Redis configured)."""


class TaskOwnership:
    """Owner records for asynchronous tasks, kept in Redis."""

    def __init__(self, client):
        # A redis.Redis created with decode_responses=True.
        self._redis = client

    def record(
        self,
        task_id: str,
        user_id: str,
        team_id: str,
        tool_name: str,
        now: Optional[float] = None,
    ) -> None:
        """Record who submitted the task. Call this before the task is queued."""
        now = time.time() if now is None else now
        index = _USER_INDEX_KEY.format(user_id=user_id)
        owner = {
            "task_id": task_id,
            "user_id": str(user_id),
            "team_id": str(team_id),
            "tool_name": tool_name,
            "submitted_at": now,
        }
        pipe = self._redis.pipeline()
        pipe.set(
            _OWNER_KEY.format(task_id=task_id), json.dumps(owner), ex=OWNER_TTL_SECONDS
        )
        pipe.zadd(index, {task_id: now})
        pipe.zremrangebyscore(index, "-inf", now - OWNER_TTL_SECONDS)
        pipe.expire(index, OWNER_TTL_SECONDS)
        pipe.execute()

    def forget(self, task_id: str, user_id: str) -> None:
        """Drop the record of a task that was never queued."""
        self._redis.delete(_OWNER_KEY.format(task_id=task_id))
        self._redis.zrem(_USER_INDEX_KEY.format(user_id=user_id), task_id)

    def owned_by(self, task_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """The task's owner record if ``user_id`` submitted it, else None.

        None covers an unknown id, an expired record, a task without a record
        and another user's task alike, so a caller cannot tell them apart.
        """
        owner = self._load(self._redis.get(_OWNER_KEY.format(task_id=task_id)))
        if owner is None or owner.get("user_id") != str(user_id):
            return None
        return owner

    def list_for(
        self, user_id: str, limit: int, now: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """The user's most recent tasks, newest first, at most ``limit``."""
        now = time.time() if now is None else now
        index = _USER_INDEX_KEY.format(user_id=user_id)
        self._redis.zremrangebyscore(index, "-inf", now - OWNER_TTL_SECONDS)
        task_ids = self._redis.zrevrange(index, 0, limit - 1)
        if not task_ids:
            return []
        records = self._redis.mget(
            [_OWNER_KEY.format(task_id=task_id) for task_id in task_ids]
        )
        owned = []
        for task_id, raw in zip(task_ids, records):
            owner = self._load(raw)
            # The index is the user's own, but the owner record decides: an
            # entry whose record has expired, or names someone else, is not
            # listed.
            if owner is None or owner.get("user_id") != str(user_id):
                self._redis.zrem(index, task_id)
                continue
            owned.append(owner)
        return owned

    def cancel(self, task_id: str) -> None:
        """Record that the task's owner cancelled it.

        Kept as long as an owner record: a task can wait in the queue, and
        the marker must be there whenever a worker takes it.
        """
        self._redis.set(
            _CANCELLED_KEY.format(task_id=task_id), "1", ex=OWNER_TTL_SECONDS
        )

    def forget_cancellation(self, task_id: str) -> None:
        """Take back a cancellation that could not be carried out."""
        self._redis.delete(_CANCELLED_KEY.format(task_id=task_id))

    def is_cancelled(self, task_id: str) -> bool:
        return bool(self._redis.get(_CANCELLED_KEY.format(task_id=task_id)))

    def cancelled_among(self, task_ids: List[str]) -> Set[str]:
        """Which of the tasks were cancelled, in one round trip."""
        if not task_ids:
            return set()
        markers = self._redis.mget(
            [_CANCELLED_KEY.format(task_id=task_id) for task_id in task_ids]
        )
        return {task_id for task_id, marker in zip(task_ids, markers) if marker}

    def count_start(self, task_id: str) -> int:
        """Count one more start of the task; return how many there were."""
        key = _STARTS_KEY.format(task_id=task_id)
        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, OWNER_TTL_SECONDS)
        return int(pipe.execute()[0])

    @staticmethod
    def _load(raw) -> Optional[Dict[str, Any]]:
        if not raw:
            return None
        try:
            owner = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return owner if isinstance(owner, dict) else None


_ownership: Optional[TaskOwnership] = None


def get_task_ownership() -> TaskOwnership:
    """The process-wide owner records, connected to the service's Redis."""
    global _ownership
    if _ownership is None:
        from app.config import settings

        if not settings.redis_url:
            raise TaskOwnershipUnavailable("REDIS_URL is not set")
        import redis

        _ownership = TaskOwnership(
            redis.Redis.from_url(settings.redis_url, decode_responses=True)
        )
    return _ownership
