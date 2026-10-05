"""The logging settings are checked before the logging module gets them (#725).

``logging.format`` and ``logging.level`` went to the logging module as they
were. A format it refuses stopped the sensor with a traceback instead of a
message; a format it accepts and cannot apply, one naming a field that no
record has, made every logging call fail: the sensor ran and logged nothing
but "--- Logging error ---" on standard error.
"""

import logging
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.core.config import (  # noqa: E402
    DataLakeConfig,
    LoggingConfig,
    SensorConfig,
    load_config,
)
from sensor.utils.logging import setup_logging  # noqa: E402


def _errors(**settings):
    return LoggingConfig(**settings).validate()


def test_the_defaults_and_the_usual_formats_are_valid():
    assert _errors() == []
    assert _errors(format="%(levelname)s %(message)s") == []
    assert _errors(format="%(asctime)s [%(process)d] %(name)s: %(message)s") == []
    assert _errors(level="debug") == []
    assert _errors(file="/var/log/security-sensor/sensor.log", max_size=0) == []


@pytest.mark.parametrize(
    "bad_format, why",
    [
        ("json", "ValueError"),  # no field at all: what the use case once set
        ("%(asctime)s %(nope)s %(message)s", "'nope'"),  # no record has it
        ("%(asctime)d %(message)s", "TypeError"),  # asctime is not a number
        ("%(message", "ValueError"),
        ("{asctime} {message}", "ValueError"),  # another style than %
    ],
)
def test_a_format_the_logging_module_cannot_apply_is_an_error(bad_format, why):
    (error,) = _errors(format=bad_format)

    assert error.startswith(f"logging.format {bad_format!r} is not a format")
    assert why in error


def test_a_format_without_the_message_is_an_error():
    (error,) = _errors(format="%(asctime)s %(levelname)s")

    assert "has no %(message)s" in error


@pytest.mark.parametrize("value", [None, 5, ["%(message)s"], "", "   "])
def test_a_format_that_is_not_text_is_an_error(value):
    (error,) = _errors(format=value)

    assert "logging.format must be a logging format" in error


@pytest.mark.parametrize("level", ["VERBOSE", "disable", "", None, 10, "Formatter"])
def test_a_level_the_logging_module_does_not_have_is_an_error(level):
    # getattr(logging, level.upper()) took "disable" for a level (it is a
    # function) and "Formatter" too.
    (error,) = _errors(level=level)

    assert "logging.level must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL" in error


@pytest.mark.parametrize("name", ["max_size", "backup_count"])
@pytest.mark.parametrize("value", [-1, "10MB", 1.5, True, None])
def test_a_rotation_setting_that_is_not_a_whole_number_is_an_error(name, value):
    (error,) = _errors(**{name: value})

    assert f"logging.{name} must be a whole number" in error


def test_a_log_file_that_is_not_a_path_is_an_error():
    assert "logging.file must be a path or null" in _errors(file="")[0]
    assert "logging.file must be a path or null" in _errors(file=5)[0]


def test_a_bad_format_stops_the_sensor_with_a_message_that_names_it(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        'data_lake:\n  endpoint: "https://gateway.example"\n'
        "logging:\n  level: INFO\n  format: json\n"
    )

    with pytest.raises(ValueError) as stopped:
        load_config(str(config))

    assert "logging.format 'json' is not a format" in str(stopped.value)
    # And the whole configuration reports it, for --validate-config and the
    # local API's /api/v1/config/validate.
    whole = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        logging=LoggingConfig(format="json", level="LOUD"),
    )
    assert len(whole.validate()) == 2


def test_the_level_from_the_environment_is_checked_too(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text('data_lake:\n  endpoint: "https://gateway.example"\n')
    monkeypatch.setenv("SENSOR_LOGGING_LEVEL", "TRACE")

    with pytest.raises(ValueError, match="logging.level must be one of"):
        load_config(str(config))


def test_a_valid_configuration_logs_with_its_format(tmp_path, capsys):
    settings = LoggingConfig(
        level="warning",
        format="%(levelname)s|%(name)s|%(message)s",
        file=str(tmp_path / "logs" / "sensor.log"),
    )
    assert settings.validate() == []
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    try:
        setup_logging(settings)
        logging.getLogger("sensor.test").info("not at this level")
        logging.getLogger("sensor.test").warning("to the console and the file")
        for handler in root.handlers:
            handler.flush()
    finally:
        for handler in root.handlers:
            if handler not in saved_handlers:
                handler.close()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)

    line = "WARNING|sensor.test|to the console and the file\n"
    assert capsys.readouterr().out == line
    assert (tmp_path / "logs" / "sensor.log").read_text() == line
