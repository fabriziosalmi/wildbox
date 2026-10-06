"""A Redis double with key expiry on a clock the tests control.

Enough of redis-py's surface for app.scan_store and the endpoints that use
it: strings with SETEX, plain sets, sorted sets and key expiry. A key past
its expiry is gone for every command, as in Redis.
"""

import math
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# app.config builds Settings() at import time, which requires these; the same
# test-only values test_check_discovery.py uses.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-at-least-32-chars-long")
os.environ.setdefault(
    "CSPM_CREDENTIAL_KEY", "dGVzdC1vbmx5LWtleS1ub3QtdXNlZC1mb3ItY3J5cHRvISE="
)


class Clock:
    def __init__(self, now):
        self.now = float(now)

    def __call__(self):
        return self.now


def _score(value):
    if value in ("-inf", float("-inf")):
        return -math.inf
    if value in ("+inf", "inf", float("inf")):
        return math.inf
    return float(value)


class FakeRedis:
    def __init__(self, clock):
        self.clock = clock
        self.values = {}
        self.sets = {}
        self.zsets = {}
        self.expiry = {}

    def ping(self):
        return True

    # -- expiry ---------------------------------------------------------
    def _alive(self, key):
        deadline = self.expiry.get(key)
        if deadline is not None and deadline <= self.clock():
            self.delete(key)
        return key in self.values or key in self.sets or key in self.zsets

    def delete(self, *keys):
        for key in keys:
            self.values.pop(key, None)
            self.sets.pop(key, None)
            self.zsets.pop(key, None)
            self.expiry.pop(key, None)

    def expire(self, key, seconds):
        if self._alive(key):
            self.expiry[key] = self.clock() + int(seconds)

    def expireat(self, key, when):
        if self._alive(key):
            self.expiry[key] = float(int(when))

    def ttl(self, key):
        if not self._alive(key):
            return -2
        if key not in self.expiry:
            return -1
        return int(self.expiry[key] - self.clock())

    # -- strings --------------------------------------------------------
    def get(self, key):
        return self.values.get(key) if self._alive(key) else None

    def setex(self, key, seconds, value):
        if not isinstance(seconds, int):
            # Redis rejects a float TTL.
            raise TypeError("value is not an integer or out of range")
        self.values[key] = value
        self.expiry[key] = self.clock() + seconds

    def keys(self, pattern):
        prefix, suffix = pattern.split("*")
        return [
            k
            for k in list(self.values)
            if self._alive(k) and k.startswith(prefix) and k.endswith(suffix)
        ]

    # -- sets -----------------------------------------------------------
    def sadd(self, key, *members):
        self._alive(key)
        self.sets.setdefault(key, set()).update(members)

    def smembers(self, key):
        return set(self.sets.get(key, set())) if self._alive(key) else set()

    # -- sorted sets ----------------------------------------------------
    def zadd(self, key, mapping):
        self._alive(key)
        self.zsets.setdefault(key, {}).update(
            {member: float(score) for member, score in mapping.items()}
        )

    def _sorted(self, key):
        if not self._alive(key):
            return []
        return sorted(self.zsets[key].items(), key=lambda item: (item[1], item[0]))

    def zrem(self, key, *members):
        if not self._alive(key):
            return 0
        removed = [m for m in members if self.zsets[key].pop(m, None) is not None]
        if not self.zsets[key]:
            self.delete(key)
        return len(removed)

    def zremrangebyscore(self, key, low, high):
        low, high = _score(low), _score(high)
        doomed = [m for m, s in self._sorted(key) if low <= s <= high]
        for member in doomed:
            del self.zsets[key][member]
        if key in self.zsets and not self.zsets[key]:
            self.delete(key)
        return len(doomed)

    def zrangebyscore(self, key, low, high):
        low, high = _score(low), _score(high)
        return [m for m, s in self._sorted(key) if low <= s <= high]

    def zrange(self, key, start, end, withscores=False):
        items = self._sorted(key)
        end = len(items) if end == -1 else end + 1
        items = items[start:end] if start >= 0 else items[start:]
        return items if withscores else [m for m, _ in items]

    def zscore(self, key, member):
        if not self._alive(key):
            return None
        return self.zsets[key].get(member)


@pytest.fixture
def clock():
    import time

    return Clock(time.time())


@pytest.fixture
def fake_redis(clock, monkeypatch):
    """A FakeRedis whose clock is also scan_store's clock."""
    from app import scan_store

    monkeypatch.setattr(scan_store, "_now", clock)
    return FakeRedis(clock)


@pytest.fixture
def world(monkeypatch, fake_redis):
    """The API and the worker on the fake Redis, with a scan in each state.

    See route_probes.py: the scans are started through the API and ended by
    the worker's own task, so what the routes read is what the service
    stores.
    """
    import route_probes

    return route_probes.build_world(monkeypatch, fake_redis)
