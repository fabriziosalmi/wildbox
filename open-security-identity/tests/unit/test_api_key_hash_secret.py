"""API-key digests are keyed by API_KEY_HASH_SECRET, not JWT_SECRET_KEY (#648).

identity fell back to JWT_SECRET_KEY whenever API_KEY_HASH_SECRET was unset,
and compose never passed API_KEY_HASH_SECRET, so every stored digest was an
HMAC keyed by the JWT secret and rotating it invalidated every API key. These
tests hold the fix in place:

- in production, identity refuses to start without API_KEY_HASH_SECRET, and
  the error names the variable without echoing any value;
- a weak, placeholder or blank value is refused;
- a digest depends on API_KEY_HASH_SECRET only, so a JWT rotation leaves it
  unchanged;
- the upgrade path holds: a key issued before the upgrade (keyed by the JWT
  secret) still verifies once API_KEY_HASH_SECRET is seeded with that JWT
  secret, and still does after the JWT secret is rotated.
"""

import os
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import app.auth as auth  # noqa: E402
from app.config import Settings  # noqa: E402

# Random-looking, 64 hex characters, as generate_secrets.py writes them.
JWT_OLD = "3f9c1e7a5b2d8f4096e1c7a3b5d9f2e48a6c0b1d3e5f7a9c2b4d6e8f0a1c3e5b"
JWT_NEW = "c4e6a8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6"
HASH_SECRET = "9d1f3b5e7a0c2e4f6b8d0a2c4e6f8b1d3a5c7e9f0b2d4a6c8e0f1b3d5a7c9e2f"
API_KEY = "wsk_ab12.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
# Known answers: HMAC-SHA256 of API_KEY keyed by HASH_SECRET and by JWT_OLD,
# computed independently of app.auth.
DIGEST_UNDER_HASH_SECRET = (
    "8ef16da4fa661c4f3e0d3912227ea6e55796eec5c058e0d57e8a7390add606e5"
)
DIGEST_UNDER_JWT_OLD = (
    "9637b1bd17a3db150f6b0d2646c06f9a0bc852c917a564d2547ec1d895498f70"
)


def _settings(monkeypatch, **env):
    """Settings read from the given environment only, never from a .env."""
    for name in ("ENVIRONMENT", "API_KEY_HASH_SECRET"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("JWT_SECRET_KEY", JWT_OLD)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings(_env_file=None)


def _use(monkeypatch, settings):
    """Make app.auth hash with these settings."""
    monkeypatch.setattr(auth, "settings", settings)


# --- production requires the secret ---------------------------------------


@pytest.mark.parametrize("environment", ["production", "Production", " production "])
def test_production_without_the_secret_refuses_to_start(monkeypatch, environment):
    with pytest.raises(ValidationError) as excinfo:
        _settings(monkeypatch, ENVIRONMENT=environment)
    message = str(excinfo.value)
    assert "API_KEY_HASH_SECRET is required" in message
    assert JWT_OLD not in message


@pytest.mark.parametrize(
    "environment", ["staging", "test", "prod", "dev", "development-eu", "", "  "]
)
def test_any_environment_that_is_not_development_requires_the_secret(
    monkeypatch, environment
):
    """The test was for the exact value "production" (#736): "staging", a
    misspelt name or an empty variable started on the fallback."""
    with pytest.raises(ValidationError) as excinfo:
        _settings(monkeypatch, ENVIRONMENT=environment)
    message = str(excinfo.value)
    assert "API_KEY_HASH_SECRET is required unless ENVIRONMENT=development" in message
    assert JWT_OLD not in message


def test_an_environment_that_is_not_declared_requires_the_secret(monkeypatch):
    """A bare `docker run`: no ENVIRONMENT at all."""
    with pytest.raises(ValidationError, match="API_KEY_HASH_SECRET is required"):
        _settings(monkeypatch)


def test_an_undeclared_environment_with_the_secret_starts(monkeypatch):
    settings = _settings(monkeypatch, API_KEY_HASH_SECRET=HASH_SECRET)
    assert settings.environment == ""
    assert settings.api_key_hash_secret == HASH_SECRET


@pytest.mark.parametrize("environment", ["development", "Development", " development "])
def test_only_development_may_start_without_the_secret(monkeypatch, environment):
    settings = _settings(monkeypatch, ENVIRONMENT=environment)
    assert settings.api_key_hash_secret is None


def test_production_with_a_blank_secret_refuses_to_start(monkeypatch):
    """Compose renders an unset variable as an empty string."""
    with pytest.raises(ValidationError, match="API_KEY_HASH_SECRET is required"):
        _settings(monkeypatch, ENVIRONMENT="production", API_KEY_HASH_SECRET="  ")


def test_production_with_the_secret_starts(monkeypatch):
    settings = _settings(
        monkeypatch, ENVIRONMENT="production", API_KEY_HASH_SECRET=HASH_SECRET
    )
    assert settings.api_key_hash_secret == HASH_SECRET


def test_development_without_the_secret_falls_back_to_the_jwt_key(monkeypatch):
    settings = _settings(monkeypatch, ENVIRONMENT="development")
    _use(monkeypatch, settings)
    assert auth.api_key_hash_secret_is_fallback() is True
    assert auth.hash_api_key(API_KEY) == DIGEST_UNDER_JWT_OLD


@pytest.mark.parametrize(
    "value, reason",
    [
        pytest.param("0f5e9d7c" * 3, "at least 32 characters", id="short"),
        pytest.param(
            "generate-with-make-generate-secrets", "placeholder", id="placeholder"
        ),
        pytest.param("ab" * 32, "too little entropy", id="low-entropy"),
    ],
)
def test_a_weak_secret_is_refused_without_echoing_it(monkeypatch, value, reason):
    with pytest.raises(ValidationError) as excinfo:
        _settings(monkeypatch, ENVIRONMENT="production", API_KEY_HASH_SECRET=value)
    message = str(excinfo.value)
    assert reason in message
    assert "API_KEY_HASH_SECRET" in message
    # Neither our message nor pydantic's input_value (hidden in Config).
    assert value not in message
    assert JWT_OLD not in message


# --- the digest is keyed by API_KEY_HASH_SECRET -----------------------------


def test_the_digest_is_keyed_by_the_hash_secret(monkeypatch):
    _use(
        monkeypatch,
        _settings(
            monkeypatch, ENVIRONMENT="production", API_KEY_HASH_SECRET=HASH_SECRET
        ),
    )
    assert auth.api_key_hash_secret_is_fallback() is False
    assert auth.hash_api_key(API_KEY) == DIGEST_UNDER_HASH_SECRET
    assert auth.hash_api_key(API_KEY) != DIGEST_UNDER_JWT_OLD


def test_a_key_created_with_the_hash_secret_verifies(monkeypatch):
    _use(
        monkeypatch,
        _settings(
            monkeypatch, ENVIRONMENT="production", API_KEY_HASH_SECRET=HASH_SECRET
        ),
    )
    full_key, _prefix, stored = auth.generate_api_key()
    assert stored == auth.hash_api_key(full_key)
    # Not what the JWT key would give.
    _use(monkeypatch, _settings(monkeypatch, ENVIRONMENT="development"))
    assert auth.hash_api_key(full_key) != stored


def test_rotating_the_jwt_key_does_not_change_a_stored_digest(monkeypatch):
    _use(
        monkeypatch,
        _settings(
            monkeypatch, ENVIRONMENT="production", API_KEY_HASH_SECRET=HASH_SECRET
        ),
    )
    full_key, _prefix, stored = auth.generate_api_key()

    _use(
        monkeypatch,
        _settings(
            monkeypatch,
            ENVIRONMENT="production",
            JWT_SECRET_KEY=JWT_NEW,
            API_KEY_HASH_SECRET=HASH_SECRET,
        ),
    )
    assert auth.settings.jwt_secret_key == JWT_NEW
    assert auth.hash_api_key(full_key) == stored


# --- the upgrade path -------------------------------------------------------


def test_a_key_issued_before_the_upgrade_verifies_after_seeding(monkeypatch):
    """Seed API_KEY_HASH_SECRET with the JWT key, then rotate the JWT key."""
    # Before: no separate secret reached identity; digests used the JWT key.
    _use(monkeypatch, _settings(monkeypatch, ENVIRONMENT="development"))
    full_key, _prefix, stored = auth.generate_api_key()

    # After `rotate_secrets.sh --secret API_KEY_HASH_SECRET --init`.
    _use(
        monkeypatch,
        _settings(monkeypatch, ENVIRONMENT="production", API_KEY_HASH_SECRET=JWT_OLD),
    )
    assert auth.hash_api_key(full_key) == stored

    # And after a later `rotate_secrets.sh --secret JWT_SECRET_KEY`.
    _use(
        monkeypatch,
        _settings(
            monkeypatch,
            ENVIRONMENT="production",
            JWT_SECRET_KEY=JWT_NEW,
            API_KEY_HASH_SECRET=JWT_OLD,
        ),
    )
    assert auth.hash_api_key(full_key) == stored


def test_without_seeding_an_old_key_stops_verifying(monkeypatch):
    """Why the upgrade step exists: an unrelated secret breaks old keys."""
    _use(monkeypatch, _settings(monkeypatch, ENVIRONMENT="development"))
    full_key, _prefix, stored = auth.generate_api_key()

    _use(
        monkeypatch,
        _settings(
            monkeypatch, ENVIRONMENT="production", API_KEY_HASH_SECRET=HASH_SECRET
        ),
    )
    assert auth.hash_api_key(full_key) != stored
