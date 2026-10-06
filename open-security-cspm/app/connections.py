"""How long the API waits for Redis and for the task queue (#778).

The clients were made without a timeout. A server that is down refuses the
connection and the route answers 503 at once; one that accepts it and never
answers (a paused container, a host that stopped, a full disk under the
append-only file) held the route until the caller gave up, and with it the
event loop, so ``/health`` and every other route waited too. Measured with a
server that accepts and never answers: no answer from any route in 13 s.

Three clients reach Redis from the API, each with its own connection pool:

- the scan store (``REDIS_URL``), made by ``redis_client`` below;
- the Celery broker (``CELERY_BROKER_URL``), through which a scan is queued,
  a cancellation is broadcast and the workers are asked whether they are up;
- the Celery result backend (``CELERY_RESULT_BACKEND``), which holds the
  state of a queued or running scan.

In the stack the three are the same server, in three roles; each can be set
to another one. ``bound_task_queue_waits`` gives the two Celery clients the
limits the first has.

The limits of the two Celery clients are for the API. The worker keeps
Celery's own: its connection to the broker is the one it waits on for tasks,
for as long as none comes. Its scan store client is made by ``redis_client``
too, since #788: without a limit a Redis that never answers held a scan's
task for ever, and the write that ends a scan, which a limit can fail, is
made again by ``app.worker`` (``FINAL_WRITE_PAUSES``).
"""

from typing import Any

import redis

# Seconds to open a connection, and seconds to wait for one reply. On the
# stack's network Redis answers in well under a millisecond, and nothing the
# API asks of it blocks. Short enough that `/health` answers a Redis that
# does not reply inside the 5 seconds `make health` waits
# (scripts/lib/health_endpoints.sh) and the 10 of the Compose health check;
# not shorter, because a reply is late on a busy host too: with 2 seconds a
# PING through Docker Desktop's port forwarding timed out once in six runs on
# a machine under load, and the answer was a 503 for a Redis that was up.
REDIS_CONNECT_TIMEOUT_SECONDS = 2.0
REDIS_READ_TIMEOUT_SECONDS = 3.0


def redis_client(url: str) -> "redis.Redis":
    """The scan store's client, with a limit on every wait.

    What the URL says wins, as it did: ``?socket_timeout=5`` in ``REDIS_URL``
    replaces the default (redis-py applies the URL's query string over the
    arguments given here). ``from_url`` does not connect.
    """
    return redis.from_url(
        url,
        decode_responses=True,
        socket_connect_timeout=REDIS_CONNECT_TIMEOUT_SECONDS,
        socket_timeout=REDIS_READ_TIMEOUT_SECONDS,
    )


def bound_task_queue_waits(celery_app: Any) -> None:
    """Give this process's Celery client the same limits, and one attempt.

    Called by the API (app.main) and by nothing else: the worker imports
    app.worker alone and keeps Celery's defaults.

    Without the timeouts a broker or a result backend that never answers
    held ``POST /api/v1/scans``, ``GET`` and ``DELETE /api/v1/scans/{id}``
    for ever. They are not a limit by themselves, because Celery tries
    again, and each attempt lasts as long as the timeout:

    - kombu opens the broker connection again after a pause of two seconds,
      then four, for as long as ``broker_connection_timeout`` has not
      passed: one attempt here, and none after the time one takes;
    - the result backend, which Celery subscribes to for every task it
      sends, reconnects twenty times a second apart: once here.

    A connection the server closed while it was idle is still replaced:
    that is the publish retry and the backend's reconnection, both kept.
    """
    conf = celery_app.conf
    conf.broker_transport_options = {
        "socket_connect_timeout": REDIS_CONNECT_TIMEOUT_SECONDS,
        "socket_timeout": REDIS_READ_TIMEOUT_SECONDS,
        "max_retries": 0,
        # What app.worker set (visibility_timeout) stays, and wins.
        **(conf.broker_transport_options or {}),
    }
    conf.broker_connection_timeout = REDIS_CONNECT_TIMEOUT_SECONDS
    conf.redis_socket_connect_timeout = REDIS_CONNECT_TIMEOUT_SECONDS
    conf.redis_socket_timeout = REDIS_READ_TIMEOUT_SECONDS
    conf.result_backend_transport_options = {
        **(conf.result_backend_transport_options or {}),
        "retry_policy": {"max_retries": 0},
    }
