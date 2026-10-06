"""Each setting is read from the variable of its own name (#665).

Twenty-nine fields of ``app/config.py`` named their variable with
``Field(env="REDIS_URL")``, the pydantic v1 form. pydantic-settings v2 ignores
it and reads a field from the variable of the field's own name, so the
settings worked only because every name matched. The argument is gone; these
tests hold what it used to say, for every field that is left, and that the
settings nothing read are no longer settings.
"""

import os
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

# Importing app.config builds Settings(), which requires this.
os.environ.setdefault("SECRET_KEY", "k" * 40)

import app  # noqa: E402
import app.config as config  # noqa: E402
from app.config import Settings  # noqa: E402

# The variable that sets each field, a value to recognise and, when the field
# is not a string, what the value is read as.
VARIABLES = {
    "APP_NAME": ("app_name", "CSPM under test", None),
    "APP_VERSION": ("app_version", "9.9.9", None),
    "ENVIRONMENT": ("environment", "staging", None),
    "DEBUG": ("debug", "true", True),
    "HOST": ("host", "127.0.0.1", None),
    "PORT": ("port", "9019", 9019),
    "WORKERS": ("workers", "2", 2),
    "REDIS_URL": ("redis_url", "redis://redis.internal:6379/7", None),
    "CELERY_BROKER_URL": ("celery_broker_url", "redis://redis.internal:6379/8", None),
    "CELERY_RESULT_BACKEND": (
        "celery_result_backend",
        "redis://redis.internal:6379/9",
        None,
    ),
    "CELERY_TASK_SERIALIZER": ("celery_task_serializer", "msgpack", None),
    "CELERY_ACCEPT_CONTENT": ("celery_accept_content", '["msgpack"]', ["msgpack"]),
    "CELERY_RESULT_SERIALIZER": ("celery_result_serializer", "msgpack", None),
    "CELERY_TIMEZONE": ("celery_timezone", "Europe/Rome", None),
    "LOG_LEVEL": ("log_level", "WARNING", None),
    "LOG_FORMAT": ("log_format", "%(message)s", None),
    "SECRET_KEY": ("secret_key", "s" * 48, None),
    "CORS_ORIGINS": (
        "cors_origins",
        '["https://dashboard.example.com"]',
        ["https://dashboard.example.com"],
    ),
    "CORS_ALLOW_CREDENTIALS": ("cors_allow_credentials", "false", False),
    "CORS_ALLOW_METHODS": ("cors_allow_methods", '["GET"]', ["GET"]),
    "CORS_ALLOW_HEADERS": ("cors_allow_headers", '["X-Request-ID"]', ["X-Request-ID"]),
    "MAX_CONCURRENT_SCANS": ("max_concurrent_scans", "2", 2),
    "SCAN_TIMEOUT_SECONDS": ("scan_timeout_seconds", "600", 600),
    "DEFAULT_SCAN_REGIONS": (
        "default_scan_regions",
        '{"aws": ["eu-south-1"]}',
        {"aws": ["eu-south-1"]},
    ),
    "CSPM_REPORT_RETENTION_DAYS": ("cspm_report_retention_days", "7", 7),
}
REMOVED = (
    "REDIS_PASSWORD",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "API_V1_PREFIX",
    "REPORTS_STORAGE_PATH",
    "PROMETHEUS_ENABLED",
    "PROMETHEUS_PORT",
    "WILDBOX_IDENTITY_URL",
    "WILDBOX_API_URL",
    "WILDBOX_GUARDIAN_URL",
)


@pytest.fixture
def clean(monkeypatch):
    for variable in tuple(VARIABLES) + REMOVED:
        if variable != "SECRET_KEY":
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
    env_file.write_text("MAX_CONCURRENT_SCANS=3\n", encoding="utf-8")

    assert Settings(_env_file=env_file).max_concurrent_scans == 3


def test_the_cloud_provider_settings_are_gone():
    """A second settings class, nine fields, read by nothing."""
    for name in ("CloudProviderSettings", "cloud_settings", "get_cloud_settings"):
        assert not hasattr(config, name), name


def test_the_secret_key_is_still_required(clean):
    clean.delenv("SECRET_KEY")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
    clean.setenv("SECRET_KEY", "short")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_the_settings_take_the_version_of_the_package(clean):
    assert Settings(_env_file=None).app_version == app.__version__
