"""Each setting is read from the variable of its own name (#665).

The fields of ``app/config.py`` named their variable with
``Field(env="REDIS_URL")``, the pydantic v1 form. pydantic-settings v2 ignores
it and reads a field from the variable of the field's own name, so the
settings worked only because every name matched. The argument is gone; these
tests hold what it used to say, for every field, and that the settings nothing
read are no longer settings.
"""

import os
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

from app.config import Settings  # noqa: E402

# The variable each field was declared to read, and a value to recognise.
VARIABLES = {
    "DEBUG": ("debug", "true", True),
    "LOG_LEVEL": ("log_level", "WARNING", "WARNING"),
    "REDIS_URL": ("redis_url", "redis://redis.internal:6379/7", None),
    "REDIS_KEY_PREFIX": ("redis_key_prefix", "soar:", None),
    "WILDBOX_API_URL": ("wildbox_api_url", "http://tools.internal:8000", None),
    "WILDBOX_DATA_URL": ("wildbox_data_url", "http://data.internal:8002", None),
    "WILDBOX_GUARDIAN_URL": (
        "wildbox_guardian_url",
        "http://guardian.internal:8013",
        None,
    ),
    "WILDBOX_AGENTS_URL": ("wildbox_agents_url", "http://agents.internal:8006", None),
    "GATEWAY_INTERNAL_SECRET": ("gateway_internal_secret", "a-secret-for-a-test", None),
    "API_HOST": ("api_host", "127.0.0.1", None),
    "API_PORT": ("api_port", "9018", 9018),
    "PLAYBOOKS_DIRECTORY": ("playbooks_directory", "/srv/playbooks", None),
    "EXECUTION_RETENTION_DAYS": ("execution_retention_days", "7", 7),
}
REMOVED = (
    "WILDBOX_SENSOR_URL",
    "API_KEY",
    "DEFAULT_STEP_TIMEOUT",
    "MAX_CONCURRENT_EXECUTIONS",
    "DRAMATIQ_PROCESSES",
    "DRAMATIQ_THREADS",
)


@pytest.fixture
def clean(monkeypatch):
    for variable in tuple(VARIABLES) + REMOVED:
        monkeypatch.delenv(variable, raising=False)
    return monkeypatch


def test_every_field_is_covered():
    """A field added later is added here, with the variable that sets it."""
    assert {field for field, _, _ in VARIABLES.values()} == set(Settings.model_fields)


@pytest.mark.parametrize("variable", sorted(VARIABLES))
def test_the_variable_sets_the_field(clean, variable):
    field, value, expected = VARIABLES[variable]
    default = getattr(Settings(_env_file=None), field)
    clean.setenv(variable, value)

    read = getattr(Settings(_env_file=None), field)

    assert read == (value if expected is None else expected)
    assert read != default, "the value would not show that the variable was read"


@pytest.mark.parametrize("variable", sorted(VARIABLES))
def test_the_variable_is_read_in_any_case(clean, variable):
    field, value, expected = VARIABLES[variable]
    clean.setenv(variable.lower(), value)

    read = getattr(Settings(_env_file=None), field)

    assert read == (value if expected is None else expected)


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


def test_the_env_file_is_still_read(clean, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("REDIS_KEY_PREFIX=from-the-file:\n", encoding="utf-8")

    assert Settings(_env_file=env_file).redis_key_prefix == "from-the-file:"
