"""The lockout counters are not kept under the address that was typed (#778).

The counter of failed logins and the lock itself were Redis keys named after
the address: ``login:attempts:<address>`` and ``login:lockout:<address>``.
The address is whatever was typed in the login form, so a password pasted
into the wrong field became a key name: readable by anyone who can list
keys, and written to Redis's append-only file and to its backups.

They are kept under a keyed digest of the address now. The lockout itself
is the same: these tests run the real helpers of ``app.token_blacklist``,
and the login and current-password checks that use them, on a Redis double
that keeps what it is asked to keep.
"""

import asyncio
import hashlib
import hmac
import os
import re
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import auth, token_blacklist, user_manager  # noqa: E402
from app.config import settings  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi_users import BaseUserManager  # noqa: E402

ADDRESS = "alice@example.com"
# What ends up in the address field by mistake.
PASTED = "Tr0ub4dor&3-pasted-in-the-wrong-field"
PASSWORD = "correct horse battery staple"
SECRET = "k" * 16 + "0123456789abcdef" * 2


class Redis:
    """The commands the lockout uses, on a dict; every key it is given."""

    def __init__(self):
        self.values = {}
        self.ttl = {}

    async def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    async def expire(self, key, seconds):
        self.ttl[key] = seconds

    async def get(self, key):
        value = self.values.get(key)
        return None if value is None else str(value)

    async def exists(self, key):
        return int(key in self.values)

    async def setex(self, key, seconds, value):
        self.values[key] = value
        self.ttl[key] = seconds

    async def delete(self, key):
        self.values.pop(key, None)
        self.ttl.pop(key, None)


@pytest.fixture
def redis(monkeypatch):
    double = Redis()

    async def get_redis():
        return double

    monkeypatch.setattr(token_blacklist, "get_redis", get_redis)
    monkeypatch.setattr(settings, "api_key_hash_secret", SECRET)
    return double


def run(coroutine):
    return asyncio.run(coroutine)


def fail(address, times=1):
    for _ in range(times):
        run(token_blacklist.record_failed_login(address))


LIMIT = settings.max_failed_login_attempts
KEY = re.compile(r"login:(attempts|lockout):[0-9a-f]{64}\Z")


# --- What Redis is given ---------------------------------------------------------


@pytest.mark.parametrize("typed", [ADDRESS, PASTED, "  Alice@Example.COM "])
def test_no_key_holds_what_was_typed(redis, typed):
    fail(typed, LIMIT)
    assert run(token_blacklist.is_account_locked(typed)) is True

    keys = sorted(redis.values)

    # The counter and the lock: two keys, each a prefix and 64 hex digits.
    assert len(keys) == 2
    assert all(KEY.match(key) for key in keys), keys
    for key in keys:
        assert typed not in key
        assert typed.strip().lower() not in key
        assert "@" not in key


def test_the_digest_is_keyed_and_is_not_the_one_the_log_line_uses(redis):
    """The log's digest can be recomputed by whoever knows the address, and
    so by whoever guesses it; a key name must not be."""
    key = token_blacklist.account_key(ADDRESS)

    assert (
        key
        == hmac.new(
            SECRET.encode(), b"login-lockout:" + ADDRESS.encode(), hashlib.sha256
        ).hexdigest()
    )
    assert key != hashlib.sha256(ADDRESS.encode()).hexdigest()
    assert not key.startswith(token_blacklist.account_digest(ADDRESS))
    # Not the digest an API key equal to the address would be stored under.
    assert key != auth.hash_api_key(ADDRESS)


def test_another_secret_gives_another_key(redis, monkeypatch):
    first = token_blacklist.account_key(ADDRESS)

    monkeypatch.setattr(settings, "api_key_hash_secret", SECRET[::-1])

    assert token_blacklist.account_key(ADDRESS) != first


def test_without_the_secret_the_key_is_keyed_as_the_api_keys_are(redis, monkeypatch):
    """Development only: Settings refuses to load without it elsewhere."""
    monkeypatch.setattr(settings, "api_key_hash_secret", None)

    assert (
        token_blacklist.account_key(ADDRESS)
        == hmac.new(
            settings.jwt_secret_key.encode(),
            b"login-lockout:" + ADDRESS.encode(),
            hashlib.sha256,
        ).hexdigest()
    )


def test_one_address_one_counter_however_it_is_typed(redis):
    for typed in (ADDRESS, "Alice@Example.com", "  alice@example.com\t"):
        fail(typed)

    (counter,) = redis.values.values()
    assert counter == 3
    assert token_blacklist.account_key(" ALICE@example.COM ") == (
        token_blacklist.account_key(ADDRESS)
    )
    assert token_blacklist.account_key("bob@example.com") != (
        token_blacklist.account_key(ADDRESS)
    )


# --- The lockout, as before ---------------------------------------------------------


def test_the_counter_expires_with_the_lockout_period_and_the_lock_too(redis):
    period = settings.account_lockout_minutes * 60

    fail(ADDRESS, LIMIT)
    assert run(token_blacklist.is_account_locked(ADDRESS)) is True

    account = token_blacklist.account_key(ADDRESS)
    assert redis.values == {
        f"login:attempts:{account}": LIMIT,
        f"login:lockout:{account}": "locked",
    }
    assert redis.ttl == {
        f"login:attempts:{account}": period,
        f"login:lockout:{account}": period,
    }


def test_an_address_is_locked_at_the_limit_and_not_before(redis):
    fail(ADDRESS, LIMIT - 1)
    assert run(token_blacklist.is_account_locked(ADDRESS)) is False

    fail(ADDRESS)
    assert run(token_blacklist.is_account_locked(ADDRESS)) is True
    # Another address is not.
    assert run(token_blacklist.is_account_locked("bob@example.com")) is False


def test_a_success_clears_the_counter(redis):
    fail(ADDRESS, LIMIT - 1)

    run(token_blacklist.clear_failed_logins(ADDRESS))

    assert redis.values == {}
    fail(ADDRESS)
    assert run(token_blacklist.is_account_locked(ADDRESS)) is False


@pytest.fixture
def accounts(redis, monkeypatch):
    """A user manager whose parent knows one account and one password."""
    user = SimpleNamespace(id=uuid.uuid4(), email=ADDRESS, hashed_password="hash")

    async def authenticate(self, credentials):
        known = credentials.username.strip().lower() == ADDRESS
        return user if known and credentials.password == PASSWORD else None

    monkeypatch.setattr(BaseUserManager, "authenticate", authenticate)
    monkeypatch.setattr(
        user_manager, "verify_password", lambda password, _hash: password == PASSWORD
    )
    return SimpleNamespace(manager=user_manager.UserManager(None), user=user)


def login(accounts, username, password):
    return run(
        accounts.manager.authenticate(
            SimpleNamespace(username=username, password=password)
        )
    )


def test_a_login_is_locked_out_after_the_limit_and_the_right_password_refused(
    redis, accounts
):
    for _ in range(LIMIT):
        assert login(accounts, ADDRESS, "wrong") is None

    with pytest.raises(HTTPException) as refused:
        login(accounts, ADDRESS, PASSWORD)

    assert refused.value.status_code == 429
    assert all(KEY.match(key) for key in redis.values), sorted(redis.values)


def test_the_login_and_the_current_password_check_share_one_counter(redis, accounts):
    """A session guessing the current password and a login guessing it count
    together (#569): both ask the helpers about the same account."""
    for _ in range(LIMIT - 1):
        assert login(accounts, "Alice@Example.com", "wrong") is None
    with pytest.raises(HTTPException) as wrong:
        run(user_manager.verify_current_password(accounts.user, "wrong too"))
    assert wrong.value.status_code == 400

    with pytest.raises(HTTPException) as refused:
        run(user_manager.verify_current_password(accounts.user, PASSWORD))

    assert refused.value.status_code == 429
    assert len(redis.values) == 2


def test_a_password_typed_as_the_address_is_counted_and_nowhere_to_be_read(
    redis, accounts
):
    assert login(accounts, PASTED, "whatever") is None

    assert len(redis.values) == 1
    stored = repr(redis.values) + repr(redis.ttl)
    assert PASTED not in stored
    assert PASTED.lower() not in stored


# --- The keys an earlier release wrote ------------------------------------------------


def test_the_keys_of_an_earlier_release_are_not_read(redis):
    """A lock in progress at the upgrade ends there: nothing looks under the
    address any more. The old keys expire on their own, within the lockout
    period they were written with."""
    redis.values[f"login:lockout:{ADDRESS}"] = "locked"
    redis.values[f"login:attempts:{ADDRESS}"] = LIMIT + 4
    before = dict(redis.values)

    assert run(token_blacklist.is_account_locked(ADDRESS)) is False
    fail(ADDRESS)
    assert run(token_blacklist.is_account_locked(ADDRESS)) is False
    run(token_blacklist.clear_failed_logins(ADDRESS))

    # Neither read nor written nor deleted.
    assert redis.values == before
