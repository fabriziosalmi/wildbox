"""The part of redis-py the responder uses, in memory.

Values are stored as redis-py returns them, as bytes. Transactions behave as
Redis's WATCH/MULTI/EXEC do under redis-py's ``Redis.transaction``: reads
before ``multi()`` run at once, commands after it are queued, and ``execute``
applies them only if no watched key was written in between -- otherwise it
raises WatchError and the transaction function runs again.

``before_commit`` lets a test play another client: it is called once, just
before the next transaction commits, and whatever it writes then counts as
a concurrent write.
"""

from redis.exceptions import ResponseError, WatchError

WRONGTYPE = "WRONGTYPE Operation against a key holding the wrong kind of value"


def _encode(value):
    if isinstance(value, bytes):
        return value
    # As redis-py encodes: a str (an ExecutionStatus too) by its value.
    return value.encode() if isinstance(value, str) else str(value).encode()


class MemoryRedis:
    def __init__(self):
        self.hashes, self.lists, self.strings = {}, {}, {}
        self.expirations = {}
        self.versions = {}
        self.before_commit = None
        self.commits = 0
        self.retries = 0

    def _touch(self, key):
        self.versions[key] = self.versions.get(key, 0) + 1

    # --- Commands ------------------------------------------------------------

    def hset(self, key, mapping):
        self.hashes.setdefault(key, {}).update(
            {k: _encode(v) for k, v in mapping.items()}
        )
        self._touch(key)

    def hget(self, key, field):
        if key in self.strings or key in self.lists:
            raise ResponseError(WRONGTYPE)
        return self.hashes.get(key, {}).get(field)

    def expire(self, key, seconds):
        self.expirations[key] = seconds

    def rpush(self, key, value):
        self.lists.setdefault(key, []).append(_encode(value))
        self._touch(key)

    def lrange(self, key, start, end):
        items = self.lists.get(key, [])
        return items[start:] if end == -1 else items[start : end + 1]

    def set(self, key, value, ex=None):
        self.strings[key] = _encode(value)
        if ex is not None:
            self.expirations[key] = ex
        self._touch(key)

    def get(self, key):
        return self.strings.get(key)

    def exists(self, *keys):
        return sum(
            1
            for key in keys
            if key in self.strings or key in self.hashes or key in self.lists
        )

    def scan_iter(self, match=None, count=None):
        import fnmatch

        keys = list(self.strings) + list(self.hashes) + list(self.lists)
        return [k.encode() for k in keys if match is None or fnmatch.fnmatch(k, match)]

    # --- Pipelines and transactions ------------------------------------------

    def pipeline(self, transaction=True):
        return _Pipeline(self, ())

    def transaction(self, func, *watches, value_from_callable=False, **kwargs):
        while True:
            pipe = _Pipeline(self, watches)
            value = func(pipe)
            try:
                result = pipe.execute()
            except WatchError:
                self.retries += 1
                continue
            return value if value_from_callable else result


class _Pipeline:
    """Immediate until multi(), queued after it; EXEC checks the watches."""

    def __init__(self, store, watches):
        self.store = store
        self.watched = {key: store.versions.get(key, 0) for key in watches}
        self.queued = None if watches else []

    def multi(self):
        self.queued = []

    def __getattr__(self, name):
        command = getattr(self.store, name)

        def call(*args, **kwargs):
            if self.queued is None:
                return command(*args, **kwargs)
            self.queued.append((command, args, kwargs))
            return self

        return call

    def execute(self):
        hook, self.store.before_commit = self.store.before_commit, None
        if hook:
            hook()
        for key, version in self.watched.items():
            if self.store.versions.get(key, 0) != version:
                raise WatchError(f"{key} changed")
        results = [command(*a, **kw) for command, a, kw in self.queued or []]
        self.store.commits += 1
        return results
