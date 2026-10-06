"""The settings are the ones the service reads, each set by its variable (#665).

``app/config.py`` declared nine settings no code read (``API_KEY_NAME``,
``LOG_FORMAT``, ``TOOL_RESULT_TTL``, ``ENABLE_CACHING``, ``DATABASE_URL``,
``ENABLE_AUDIT_LOGGING``, ``ENABLE_SECURITY_HEADERS``, ``TOOLS_DIRECTORY``,
``AUTO_RELOAD_TOOLS``) and a ``get_secret_key()`` that read a field which no
longer existed. Its validators were pydantic v1 ``@validator``s. These tests
hold that every field left is set by the variable of its name, that the
validators still do what they did, and that the rest is gone.
"""

import os
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

GOOD_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
os.environ.setdefault("API_KEY", GOOD_KEY)

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from app.config import Settings  # noqa: E402

OTHER_KEY = "f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1"
# The variable that sets each field, a value to recognise and, when the field
# is not a string, what the value is read as.
VARIABLES = {
    "API_KEY": ("api_key", OTHER_KEY, None),
    "HOST": ("host", "0.0.0.0", None),  # nosec B104 - a value, bound to nothing
    "PORT": ("port", "9000", 9000),
    "DEBUG": ("debug", "true", True),
    "ENVIRONMENT": ("environment", "staging", None),
    "LOG_LEVEL": ("log_level", "warning", "WARNING"),
    "CORS_ORIGINS": (
        "cors_origins",
        "https://a.example, https://b.example",
        ["https://a.example", "https://b.example"],
    ),
    "CORS_ALLOW_CREDENTIALS": ("cors_allow_credentials", "false", False),
    "EXECUTION_HISTORY_LIMIT": ("execution_history_limit", "50", 50),
    "TOOL_TIMEOUT": ("tool_timeout", "120", 120),
    "MAX_CONCURRENT_TOOLS": ("max_concurrent_tools", "3", 3),
    "REDIS_URL": ("redis_url", "redis://redis.internal:6379/9", None),
    "TOOLS_ALLOWED_INTERNAL_TARGETS": (
        "tools_allowed_internal_targets",
        "10.20.0.0/16,lab-dc01",
        None,
    ),
}
REMOVED = (
    "API_KEY_NAME",
    "LOG_FORMAT",
    "TOOL_RESULT_TTL",
    "ENABLE_CACHING",
    "DATABASE_URL",
    "ENABLE_AUDIT_LOGGING",
    "ENABLE_SECURITY_HEADERS",
    "TOOLS_DIRECTORY",
    "AUTO_RELOAD_TOOLS",
)


@pytest.fixture
def clean(monkeypatch):
    for variable in tuple(VARIABLES) + REMOVED:
        if variable != "API_KEY":
            monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("API_KEY", GOOD_KEY)
    return monkeypatch


def value_of(settings, field):
    value = getattr(settings, field)
    return value.get_secret_value() if field == "api_key" else value


def test_every_field_is_covered():
    """A field added later is added here, with the variable that sets it."""
    assert {field for field, _, _ in VARIABLES.values()} == set(Settings.model_fields)


@pytest.mark.parametrize("variable", sorted(VARIABLES))
def test_the_variable_sets_the_field(clean, variable):
    field, value, expected = VARIABLES[variable]
    default = value_of(Settings(_env_file=None), field)
    clean.setenv(variable, value)

    read = value_of(Settings(_env_file=None), field)

    assert read == (value if expected is None else expected)
    assert read != default, "the value would not show that the variable was read"


@pytest.mark.parametrize("variable", REMOVED)
def test_a_setting_nothing_read_is_gone(clean, variable):
    assert variable.lower() not in Settings.model_fields
    # In the environment it is ignored, as any variable that is not a setting.
    clean.setenv(variable, "1")
    Settings(_env_file=None)


@pytest.mark.parametrize("variable", REMOVED)
def test_a_removed_setting_in_an_env_file_stops_the_service(clean, tmp_path, variable):
    """The settings refuse a key they do not know in a .env file, by name."""
    env_file = tmp_path / ".env"
    env_file.write_text(f"{variable}=1\n", encoding="utf-8")

    with pytest.raises(ValidationError) as refused:
        Settings(_env_file=env_file)

    assert [error["loc"] for error in refused.value.errors()] == [(variable.lower(),)]


def test_get_secret_key_is_gone():
    """It returned ``self.secret_key``, a field removed long before it."""
    assert not hasattr(Settings, "get_secret_key")
    assert "secret_key" not in Settings.model_fields


# --- the validators, after their conversion from @validator --------------------


def test_the_validators_are_pydantic_v2_ones():
    decorators = Settings.__pydantic_decorators__

    assert decorators.validators == {}
    assert {
        field
        for decorator in decorators.field_validators.values()
        for field in decorator.info.fields
    } == {
        "tools_allowed_internal_targets",
        "log_level",
        "environment",
        "api_key",
        "cors_origins",
    }


@pytest.mark.parametrize(
    "variable, value, message",
    [
        ("LOG_LEVEL", "loud", "log_level must be one of"),
        ("ENVIRONMENT", "prod", "environment must be one of"),
        ("ENVIRONMENT", "", "environment must be one of"),
        ("API_KEY", "x" * 40, "insufficient entropy"),
        ("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2-default-9", "weak pattern"),
        ("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1", "at least 32 characters"),
        ("TOOLS_ALLOWED_INTERNAL_TARGETS", "10.0.0.0/33", ""),
    ],
)
def test_a_value_a_validator_refuses_stops_the_settings(
    clean, variable, value, message
):
    clean.setenv(variable, value)

    with pytest.raises(ValidationError) as refused:
        Settings(_env_file=None)

    assert message in str(refused.value)


def test_an_undeclared_environment_is_neither_development_nor_production(clean):
    settings = Settings(_env_file=None)

    assert settings.environment in ("", None)
    assert settings.production_checks_apply() is True
    assert settings.is_development() is False


def test_the_env_example_is_a_file_the_settings_accept(clean, tmp_path):
    """Every line of .env.example names a setting: a copy of it, with a real
    key in place of the placeholder, starts the service."""
    example = (SERVICE_ROOT / ".env.example").read_text(encoding="utf-8")
    lines = [
        f"API_KEY={GOOD_KEY}" if line.startswith("API_KEY=") else line
        for line in example.splitlines()
    ]
    env_file = tmp_path / ".env"
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    clean.delenv("API_KEY")

    settings = Settings(_env_file=env_file)

    assert settings.get_api_key() == GOOD_KEY
    assert settings.max_concurrent_tools == 10
