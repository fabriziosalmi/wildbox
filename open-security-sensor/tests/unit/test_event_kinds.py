"""An event is enriched and filtered for what it is, not for what its type contains (#725).

The processor chose by substring: a type containing "network" or "socket" was
a connection, "process" a process, "file" a file change. The log forwarder's
types are ``log.<source name>``, and a source is named by its operator, so a
log line could be given a connection category, a file's risk level, or be
dropped as a noisy system process.
"""

import asyncio
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.collectors.osquery_manager import OsqueryManager  # noqa: E402
from sensor.core.config import DataLakeConfig, SensorConfig  # noqa: E402
from sensor.pipeline.data_processor import (  # noqa: E402
    FILE_EVENT_TYPES,
    DataProcessor,
    event_kind,
)


@pytest.fixture
def processor():
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key="")
    )
    return DataProcessor(config, asyncio.Queue(), asyncio.Queue())


def _log_line(source_name, **data):
    return {
        "type": f"log.{source_name}",
        "source": "log_forwarder",
        "data": dict({"raw_message": "a line of a log"}, **data),
        "metadata": {"log_source": source_name},
    }


@pytest.mark.parametrize(
    "source_name",
    [
        "network_devices",
        "socket",
        "process_audit",
        "file_server",
        "profile",  # contains "file"
        "network.firewall",
        "process_events.fake",
        "file_created",
    ],
)
@pytest.mark.asyncio
async def test_a_log_line_is_not_enriched_as_something_else(processor, source_name):
    event = _log_line(source_name, path="/etc/passwd", name="nginx", remote_port=443)

    processed = await processor._process_single_event(event)

    # main: connection_category, process_category, risk_indicators or
    # file_category and risk_level, depending on the source's name.
    assert processed["data"] == {
        "raw_message": "a line of a log",
        "path": "/etc/passwd",
        "name": "nginx",
        "remote_port": 443,
    }
    assert event_kind(event["type"]) is None


@pytest.mark.parametrize("source_name", ["process_audit", "subprocess", "processes"])
@pytest.mark.asyncio
async def test_a_log_line_is_not_dropped_as_a_noisy_process(processor, source_name):
    # A journal entry of a source so named, about systemd: main filtered it
    # out, because "systemd" is a process the processor finds noisy.
    event = _log_line(source_name, name="systemd-logind", cmdline="[kworker/0:1]")

    processed = await processor._process_single_event(event)

    assert processed is not None
    assert processed["data"]["name"] == "systemd-logind"


@pytest.mark.asyncio
async def test_the_collectors_own_events_are_still_enriched(processor):
    connection = await processor._process_single_event(
        {
            "type": "network.process_open_sockets",
            "source": "osquery",
            "data": [{"remote_address": "", "remote_port": 443, "name": "systemd"}],
        }
    )
    process = await processor._process_single_event(
        {
            "type": "process_events.process_tree",
            "source": "osquery",
            "data": [{"name": "python3", "path": "/usr/bin/python3", "cmdline": "x"}],
        }
    )
    changed = await processor._process_single_event(
        {
            "type": "file_modified",
            "source": "fim",
            "data": {"path": "/etc/passwd", "changes": ["content"]},
        }
    )

    assert connection["data"][0]["connection_category"] == "web"
    # A socket is not a process: the socket of a process the filter finds
    # noisy is still reported. (By substring, "process_open_sockets" was
    # filtered as a list of processes.)
    assert connection["data"][0]["name"] == "systemd"
    assert process["data"][0]["process_category"] == "interpreter"
    assert changed["data"]["file_category"] == "system_config"
    assert changed["data"]["risk_level"] == "critical"


@pytest.mark.asyncio
async def test_noisy_processes_are_still_filtered_from_process_events(processor):
    event = {
        "type": "process_events.process_tree",
        "source": "osquery",
        "data": [
            {"name": "systemd", "path": "/usr/lib/systemd/systemd", "cmdline": ""},
            {"name": "nginx", "path": "/usr/sbin/nginx", "cmdline": "nginx"},
        ],
    }

    processed = await processor._process_single_event(event)

    assert [item["name"] for item in processed["data"]] == ["nginx"]


def test_the_kinds_are_the_types_the_collectors_emit():
    assert {event_kind(kind) for kind in FILE_EVENT_TYPES} == {"file"}
    assert event_kind("process_events.process_events") == "process"
    assert event_kind("network.socket_events") == "network"
    for other in (
        "user_events.logged_in_users",
        "system_inventory.kernel_modules",
        "log.journal",
        "network",  # a pack with no query is not a type osquery events have
        "network.",
        "file_",
        "File_Created",
        "",
        None,
        7,
        ["network.socket_events"],
    ):
        assert event_kind(other) is None, other


def test_every_osquery_pack_the_sensor_runs_has_the_kind_its_name_says():
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key="")
    )
    packs = OsqueryManager(config, asyncio.Queue()).query_packs

    kinds = {
        pack: {event_kind(f"{pack}.{query}") for query in definition["queries"]}
        for pack, definition in packs.items()
    }

    assert kinds == {
        "process_events": {"process"},
        "network": {"network"},
        "user_events": {None},
        "system_inventory": {None},
    }
