"""The scheduler guardian-beat runs: DatabaseScheduler plus a heartbeat (#545).

A beat process can be alive and stuck -- blocked on a socket, or its loop
dead in a thread -- and a process-liveness check would still pass while no
task is ever sent. This scheduler touches a file after every completed
scheduler tick, and the container health check fails once the file is
older than a minute. DatabaseScheduler ticks at least every 5 seconds
(its max_interval), so a healthy beat refreshes the file well within that.

Everything else is django-celery-beat's DatabaseScheduler unchanged.
"""

import os

from django_celery_beat.schedulers import DatabaseScheduler

HEARTBEAT_FILE = os.getenv(
    "GUARDIAN_BEAT_HEARTBEAT_FILE", "/tmp/guardian-beat.heartbeat"  # nosec B108
)


def touch(path):
    with open(path, "a"):
        pass
    os.utime(path, None)


class HeartbeatDatabaseScheduler(DatabaseScheduler):
    """DatabaseScheduler that records each completed tick in HEARTBEAT_FILE."""

    def tick(self, *args, **kwargs):
        interval = super().tick(*args, **kwargs)
        try:
            touch(HEARTBEAT_FILE)
        except OSError:
            # The health check reports a missing heartbeat; scheduling goes on.
            pass
        return interval
