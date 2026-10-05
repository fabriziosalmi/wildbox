"""The ``log_sources`` section is part of the sensor's configuration (#638).

It used to be ignored: ``sensor/core/config.py`` had no such field, and the
log forwarder built a fixed list of paths per platform. An operator who
pointed ``log_sources`` at an application's log had the sensor read
``/var/log/syslog`` instead and never learned why nothing arrived.

What these tests pin:

* a configured source is what the forwarder reads, and the fixed paths are
  not read beside it;
* the fixed paths remain the default when the section is absent, so a
  deployment that never wrote one reads what it read before;
* a section the sensor cannot understand stops it at start-up, with a message
  naming each source at fault, as an unusable ``data_lake`` does.
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest
import yaml

SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SERVICE_ROOT.parent
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.api.local_api import LocalAPI  # noqa: E402
from sensor.collectors import log_forwarder  # noqa: E402
from sensor.collectors.log_forwarder import LogForwarder  # noqa: E402
from sensor.core.config import (  # noqa: E402
    LogSourceConfig,
    load_config,
    log_source_root,
    parse_log_sources,
)

_UNSET = object()


def _config(tmp_path, log_sources=_UNSET, **extra):
    data = {
        "data_lake": {"endpoint": "https://gateway.example"},
        "collection": {"log_forwarding": True},
    }
    if log_sources is not _UNSET:
        data["log_sources"] = log_sources
    data.update(extra)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data))
    return load_config(str(path))


def _platform(monkeypatch, name):
    for candidate in ("linux", "windows", "macos"):
        monkeypatch.setattr(
            log_forwarder, f"is_{candidate}", lambda match=(candidate == name): match
        )


def _read(config):
    """(name, type, path) of what a forwarder with this configuration reads."""
    forwarder = LogForwarder(config, asyncio.Queue())
    return [(s.name, s.type, s.path) for s in forwarder.log_sources]


def _errors(tmp_path, log_sources):
    with pytest.raises(ValueError) as refused:
        _config(tmp_path, log_sources)
    return str(refused.value)


# -- the issue ------------------------------------------------------------


def test_a_configured_source_is_read_and_the_fixed_paths_are_not(tmp_path, monkeypatch):
    _platform(monkeypatch, "linux")
    access_log = str(tmp_path / "access.log")

    config = _config(
        tmp_path,
        [
            {
                "name": "nginx_access",
                "type": "file",
                "path": access_log,
                "format": "nginx",
            }
        ],
    )

    # On main: [syslog, auth, journald], whatever the section said.
    assert _read(config) == [("nginx_access", "file", access_log)]


def test_the_fixed_paths_are_the_default_when_the_section_is_absent(
    tmp_path, monkeypatch
):
    config = _config(tmp_path)
    assert config.log_sources is None

    _platform(monkeypatch, "linux")
    assert _read(config) == [
        ("syslog", "file", "/var/log/syslog"),
        ("auth", "file", "/var/log/auth.log"),
        ("journald", "journald", None),
    ]
    _platform(monkeypatch, "macos")
    assert _read(config) == [
        ("system_log", "file", "/var/log/system.log"),
        ("unified_log", "unified_log", None),
    ]
    _platform(monkeypatch, "windows")
    assert _read(config) == [
        ("security", "windows_event", None),
        ("system", "windows_event", None),
        ("application", "windows_event", None),
    ]


def test_the_default_sources_read_existing_files_from_their_end(monkeypatch):
    _platform(monkeypatch, "linux")

    syslog = log_forwarder.default_log_sources()[0]

    assert (syslog.format, syslog.read_from, syslog.enabled) == ("syslog", "end", True)


# -- the schema -----------------------------------------------------------


def test_a_source_has_a_path_a_format_and_an_enabled_flag(tmp_path):
    config = _config(
        tmp_path,
        [
            {
                "name": "nginx_access",
                "type": "file",
                "path": "/var/log/nginx/access.log",
                "format": "nginx",
                "enabled": True,
                "read_from": "beginning",
            }
        ],
    )

    assert config.log_sources == [
        LogSourceConfig(
            name="nginx_access",
            type="file",
            path="/var/log/nginx/access.log",
            format="nginx",
            enabled=True,
            read_from="beginning",
        )
    ]


def test_the_type_defaults_to_file_and_the_format_to_raw(tmp_path):
    config = _config(tmp_path, [{"name": "app", "path": "/srv/app/logs/*.log"}])

    (source,) = config.log_sources
    assert (source.type, source.format, source.enabled, source.read_from) == (
        "file",
        "raw",
        True,
        "end",
    )


def test_a_disabled_source_is_not_read(tmp_path):
    config = _config(
        tmp_path,
        [
            {"name": "on", "path": "/var/log/on.log"},
            {"name": "off", "path": "/var/log/off.log", "enabled": False},
        ],
    )

    assert [name for name, _, _ in _read(config)] == ["on"]


def test_an_empty_list_reads_nothing_not_the_defaults(tmp_path, monkeypatch):
    _platform(monkeypatch, "linux")

    config = _config(tmp_path, [])

    assert config.log_sources == []
    assert _read(config) == []


def test_a_system_log_is_a_source_too(tmp_path):
    config = _config(
        tmp_path,
        [
            {"name": "journal", "type": "journald"},
            {"name": "security", "type": "windows_event", "log_name": "Security"},
            {"name": "unified", "type": "unified_log"},
        ],
    )

    assert [(s.type, s.format, s.log_name) for s in config.log_sources] == [
        ("journald", "json", None),
        ("windows_event", "windows_event", "Security"),
        ("unified_log", "json", None),
    ]


# -- what stops the sensor ------------------------------------------------


def test_a_section_with_no_value_is_refused(tmp_path):
    # 'log_sources:' followed by entries that are all commented out. Neither
    # reading of it is safe to guess: the defaults forward logs nobody
    # listed, an empty list silences a sensor that was forwarding.
    message = _errors(tmp_path, None)

    assert "log_sources is present but empty" in message
    assert "log_sources: []" in message


def test_a_section_that_is_not_a_list_is_refused(tmp_path):
    message = _errors(tmp_path, {"nginx": "/var/log/nginx/access.log"})

    assert "log_sources must be a list" in message


def test_an_unknown_type_is_refused_and_names_the_source(tmp_path):
    message = _errors(
        tmp_path, [{"name": "app", "type": "tcp", "path": "/var/log/app.log"}]
    )

    assert "log_sources[0] ('app')" in message
    assert "unknown type 'tcp'" in message
    assert "file, journald, windows_event, unified_log" in message


def test_an_unknown_format_is_refused(tmp_path):
    message = _errors(
        tmp_path, [{"name": "app", "path": "/var/log/app.log", "format": "json"}]
    )

    assert "log_sources[0] ('app')" in message
    assert "unknown format 'json'" in message
    assert "syslog, nginx, apache, raw" in message


def test_a_misspelled_key_is_refused_rather_than_ignored(tmp_path):
    # Ignored, 'enable: false' would leave the source forwarding its file.
    message = _errors(
        tmp_path, [{"name": "auth", "path": "/var/log/auth.log", "enable": False}]
    )

    assert "unknown key(s) enable" in message


@pytest.mark.parametrize("enabled", ["false", "no", 0, None])
def test_enabled_must_be_a_boolean(tmp_path, enabled):
    message = _errors(
        tmp_path, [{"name": "auth", "path": "/var/log/auth.log", "enabled": enabled}]
    )

    assert "enabled must be true or false" in message


@pytest.mark.parametrize("name", [None, "", "has space", "-leading", "x" * 65, 7])
def test_a_source_needs_a_name_that_can_be_an_event_type(tmp_path, name):
    entry = {"path": "/var/log/app.log"}
    if name is not None:
        entry["name"] = name

    assert "name is required" in _errors(tmp_path, [entry])


def test_two_sources_cannot_share_a_name(tmp_path):
    message = _errors(
        tmp_path,
        [
            {"name": "app", "path": "/var/log/a.log"},
            {"name": "app", "path": "/var/log/b.log"},
        ],
    )

    assert "log_sources[1] ('app')" in message
    assert "used by an earlier source" in message


@pytest.mark.parametrize(
    "path, problem",
    [
        (None, "path is required"),
        ("", "path is required"),
        (["/var/log/a.log"], "path is required"),
        ("logs/access.log", "path must be absolute"),
        ("/var/log/**/*.log", "'**' is not supported"),
        ("/*.log", "must name the directory it reads"),
        ("/*/secrets", "must name the directory it reads"),
        ("/var/log/app\x00.log", "NUL"),
    ],
)
def test_a_path_the_forwarder_cannot_confine_is_refused(tmp_path, path, problem):
    entry = {"name": "app"}
    if path is not None:
        entry["path"] = path

    assert problem in _errors(tmp_path, [entry])


def test_read_from_is_end_or_beginning(tmp_path):
    message = _errors(
        tmp_path, [{"name": "app", "path": "/var/log/app.log", "read_from": "start"}]
    )

    assert "read_from must be one of end, beginning" in message


@pytest.mark.parametrize(
    "entry, problem",
    [
        ({"type": "journald", "path": "/var/log/journal"}, "path applies to type file"),
        ({"type": "journald", "format": "syslog"}, "has the format json"),
        (
            {"type": "journald", "log_name": "System"},
            "log_name applies to type windows",
        ),
        ({"type": "windows_event"}, "log_name is required"),
        ({"type": "windows_event", "log_name": 'x"; rm'}, "log_name is required"),
        (
            {"type": "file", "path": "/a/b.log", "log_name": "System"},
            "log_name applies",
        ),
    ],
)
def test_a_key_that_does_not_apply_to_the_type_is_refused(tmp_path, entry, problem):
    assert problem in _errors(tmp_path, [dict(entry, name="source")])


def test_an_entry_that_is_not_a_mapping_is_refused(tmp_path):
    assert "log_sources[0] must be a mapping" in _errors(
        tmp_path, ["/var/log/nginx/access.log"]
    )


def test_too_many_sources_are_refused(tmp_path):
    sources = [{"name": f"s{i}", "path": f"/var/log/{i}.log"} for i in range(65)]

    assert "at most 64" in _errors(tmp_path, sources)


def test_every_source_at_fault_is_reported_in_one_start(tmp_path):
    message = _errors(
        tmp_path,
        [
            {"name": "good", "path": "/var/log/good.log"},
            {"name": "first", "type": "tcp"},
            {"name": "second", "path": "relative.log"},
        ],
    )

    assert "log_sources[1] ('first'): unknown type 'tcp'" in message
    assert "log_sources[2] ('second'): path must be absolute" in message
    assert "good" not in message


def test_a_bad_section_is_reported_with_a_bad_destination(tmp_path):
    with pytest.raises(ValueError) as refused:
        _config(
            tmp_path,
            [{"name": "app", "type": "tcp"}],
            data_lake={"endpoint": "http://gateway.example"},
        )

    assert "https://" in str(refused.value)
    assert "unknown type 'tcp'" in str(refused.value)


def test_a_path_that_does_not_exist_does_not_stop_the_sensor(tmp_path):
    # A log appears when its application first writes it, and is rotated
    # while the sensor runs: the forwarder reports it and keeps looking.
    config = _config(
        tmp_path, [{"name": "later", "path": str(tmp_path / "absent" / "app.log")}]
    )

    assert config.validate() == []


def test_parse_reports_nothing_for_a_valid_section():
    sources, errors = parse_log_sources([{"name": "a", "path": "/var/log/a.log"}])

    assert errors == []
    assert [source.name for source in sources] == ["a"]


@pytest.mark.parametrize(
    "path, root",
    [
        ("/var/log/nginx/access.log", "/var/log/nginx"),
        ("/var/log/nginx/*.log", "/var/log/nginx"),
        ("/var/www/*/logs/access.log", "/var/www"),
        ("/var/log/app-[0-9]/out.log", "/var/log"),
        ("/app.log", "/"),
    ],
)
def test_the_directory_a_source_is_confined_to(path, root):
    assert log_source_root(path) == root


# -- no other way in ------------------------------------------------------


def test_no_environment_variable_sets_the_sources(tmp_path, monkeypatch):
    # What the sensor reads from the host is the configuration file's to
    # say, and only its: nothing in the environment adds a path.
    for name in ("SENSOR_LOG_SOURCES", "SENSOR_LOG_SOURCES_PATH", "LOG_SOURCES"):
        monkeypatch.setenv(name, "/etc/shadow")

    assert _config(tmp_path).log_sources is None
    assert _config(tmp_path, []).log_sources == []


@pytest.mark.asyncio
async def test_the_local_api_shows_the_sources_the_sensor_was_given(tmp_path):
    configured = _config(tmp_path, [{"name": "app", "path": "/srv/app/logs/*.log"}])
    absent = _config(tmp_path)

    async def shown(config):
        response = await LocalAPI(config, agent=None)._get_config_handler(None)
        return json.loads(response.text)["log_sources"]

    assert await shown(configured) == [
        {
            "name": "app",
            "type": "file",
            "path": "/srv/app/logs/*.log",
            "format": "raw",
            "enabled": True,
            "read_from": "end",
        }
    ]
    # null: the platform's defaults, not "no source".
    assert await shown(absent) is None


# -- the shipped files ----------------------------------------------------


@pytest.mark.parametrize(
    "shipped", ["config.yaml.example", "config.yaml", "config.docker.yaml"]
)
def test_the_shipped_configurations_keep_the_default_sources(
    shipped, tmp_path, monkeypatch
):
    # They only document the section, commented out: uncommenting the key
    # without an entry would be the refused "present but empty" case.
    # (The data directory the container's configurations name is the
    # container's: here it is this test's.)
    monkeypatch.setenv("SENSOR_DATA_DIR", str(tmp_path))
    config = load_config(str(SERVICE_ROOT / shipped))

    assert config.log_sources is None
    assert config.collection.log_forwarding is False


def test_the_use_case_configuration_reads_the_nginx_access_log():
    use_case = REPO_ROOT / "use-cases/web-attack-detection/sensor-config/config.yaml"
    if not use_case.exists():
        pytest.skip("not a repository checkout: the use case is not here")
    config = load_config(str(use_case))

    assert config.collection.log_forwarding is True
    assert [(s.name, s.path, s.format) for s in config.log_sources if s.enabled] == [
        ("nginx_access", "/var/log/nginx/access.log", "nginx")
    ]
    # A logging format with no placeholder would print that word for every
    # record, the forwarder's warnings about a source included.
    assert "%(message)s" in config.logging.format
