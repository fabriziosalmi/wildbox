"""The settings keep their configuration, written the pydantic v2 way (#665).

``app/config.py`` and five schemas carried a nested ``class Config``, the
pydantic v1 form, which v2 still honors and announces it will drop. The
settings' one said three things: read ``.env``, read variables in any case,
and never print the value being validated, secrets included, in a validation
error. They are a ``SettingsConfigDict`` now. These tests hold the three, and
that each field is still set by the variable of its name.
"""

import os
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import schemas  # noqa: E402
from app.config import Settings  # noqa: E402

SECRET = "Zx9Qw7Er5Ty3Ui1Op0As8Df6Gh4Jk2Lz"
# The variable that sets each field, a value to recognise and, when the field
# is not a string, what the value is read as.
VARIABLES = {
    "APP_NAME": ("app_name", "identity under test", None),
    "APP_VERSION": ("app_version", "9.9.9", None),
    "DEBUG": ("debug", "true", True),
    "PORT": ("port", "9001", 9001),
    "ENVIRONMENT": ("environment", "staging", None),
    "DATABASE_URL": (
        "database_url",
        "postgresql://u:p@db.internal:5432/identity",
        None,
    ),
    "JWT_SECRET_KEY": ("jwt_secret_key", "j" * 40, None),
    "API_KEY_HASH_SECRET": ("api_key_hash_secret", SECRET, None),
    "JWT_ALGORITHM": ("jwt_algorithm", "HS512", None),
    "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": ("jwt_access_token_expire_minutes", "5", 5),
    "REDIS_URL": ("redis_url", "redis://redis.internal:6379/9", None),
    "MAX_FAILED_LOGIN_ATTEMPTS": ("max_failed_login_attempts", "3", 3),
    "ACCOUNT_LOCKOUT_MINUTES": ("account_lockout_minutes", "60", 60),
    "API_V1_PREFIX": ("api_v1_prefix", "/api/v9", None),
    "INTERNAL_API_PREFIX": ("internal_api_prefix", "/private", None),
    "GATEWAY_INTERNAL_SECRET": ("gateway_internal_secret", "g" * 40, None),
    "GUARDIAN_CONTACTS_SECRET": ("guardian_contacts_secret", SECRET[::-1], None),
    "CORS_ORIGINS": (
        "cors_origins",
        "https://a.example,https://b.example",
        ["https://a.example", "https://b.example"],
    ),
    "CORS_ALLOW_CREDENTIALS": ("cors_allow_credentials", "false", False),
    "CORS_ALLOW_METHODS": ("cors_allow_methods", '["GET"]', ["GET"]),
    "CORS_ALLOW_HEADERS": ("cors_allow_headers", '["X-Request-ID"]', ["X-Request-ID"]),
}


@pytest.fixture
def clean(monkeypatch):
    for variable in VARIABLES:
        if variable not in ("DATABASE_URL", "JWT_SECRET_KEY", "ENVIRONMENT"):
            monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")
    return monkeypatch


def test_every_field_is_covered():
    """A field added later is added here, with the variable that sets it."""
    assert {field for field, _, _ in VARIABLES.values()} == set(Settings.model_fields)


@pytest.mark.parametrize("variable", sorted(VARIABLES))
def test_the_variable_sets_the_field(clean, variable):
    field, value, expected = VARIABLES[variable]
    default = getattr(Settings(_env_file=None), field)
    if variable == "ENVIRONMENT":
        # Outside development the service does not start without this one.
        clean.setenv("API_KEY_HASH_SECRET", SECRET)
    clean.setenv(variable, value)

    read = getattr(Settings(_env_file=None), field)

    assert read == (value if expected is None else expected)
    assert read != default, "the value would not show that the variable was read"


def test_a_variable_is_read_in_any_case(clean):
    clean.setenv("max_failed_login_attempts", "7")

    assert Settings(_env_file=None).max_failed_login_attempts == 7


def test_the_env_file_is_read(clean, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("ACCOUNT_LOCKOUT_MINUTES=45\n", encoding="utf-8")

    assert Settings(_env_file=env_file).account_lockout_minutes == 45
    assert Settings.model_config["env_file"] == ".env"


def test_a_validation_error_does_not_print_the_value(clean):
    """hide_input_in_errors: the traceback of a refused start goes to the log."""
    clean.setenv("JWT_SECRET_KEY", "short-and-secret")

    with pytest.raises(ValidationError) as refused:
        Settings(_env_file=None)

    assert "jwt_secret_key" in str(refused.value)
    assert "short-and-secret" not in str(refused.value)
    assert "input_value" not in str(refused.value)


def test_no_model_keeps_a_v1_config_class():
    assert "Config" not in vars(Settings)
    for name in (
        "UserRead",
        "UserResponse",
        "TeamResponse",
        "TeamMembershipResponse",
        "ApiKeyResponse",
    ):
        model = getattr(schemas, name)
        assert "Config" not in vars(model), name
        # What each one said: build the answer from an ORM row.
        assert model.model_config.get("from_attributes") is True, name
