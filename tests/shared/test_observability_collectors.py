"""A service can export, from ``/metrics``, values its process does not hold.

The tools service counts its asynchronous runs in Redis, where its workers
write them, and its API process serves the counts (#721). That needs two
things of the shared ``/metrics`` route: a way to add a collector to the
registry it serves, and for collecting to happen off the event loop, since
such a collector reads from the network on every scrape.
"""

import asyncio
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
from open_security_shared import observability
from open_security_shared.observability import (
    install_observability,
    metrics_response,
    register_collector,
)
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.parser import text_string_to_metric_families


class Collector:
    """One gauge, and where each collection ran."""

    def __init__(self, value=1.0):
        self.name = f"wildbox_test_collector_{uuid.uuid4().hex}"
        self.value = value
        self.collected_on_the_event_loop = []

    def collect(self):
        try:
            asyncio.get_running_loop()
            self.collected_on_the_event_loop.append(True)
        except RuntimeError:
            self.collected_on_the_event_loop.append(False)
        family = GaugeMetricFamily(self.name, "A value read when scraped.")
        family.add_metric([], self.value)
        return [family]


def exported(text):
    return {
        sample.name: sample.value
        for family in text_string_to_metric_families(text)
        for sample in family.samples
    }


def test_a_registered_collector_is_served_with_the_other_metrics():
    collector = Collector(value=7)

    assert register_collector(collector.name, collector) is True

    values = exported(metrics_response().body.decode())
    assert values[collector.name] == 7
    # Read at every scrape, not once.
    collector.value = 9
    assert exported(metrics_response().body.decode())[collector.name] == 9


def test_a_name_is_registered_once():
    """An application built twice in one process must not export twice."""
    first, second = Collector(value=1), Collector(value=2)
    name = f"once-{uuid.uuid4().hex}"

    assert register_collector(name, first) is True
    assert register_collector(name, second) is False

    values = exported(metrics_response().body.decode())
    assert values[first.name] == 1
    assert second.name not in values


def test_the_metrics_route_collects_off_the_event_loop():
    """A collector that waits on a store must not stall every other request."""
    collector = Collector()
    register_collector(collector.name, collector)
    app = FastAPI()
    install_observability(app, service_name="shared-test")

    response = TestClient(app).get("/metrics")

    assert response.status_code == 200
    assert exported(response.text)[collector.name] == 1
    assert collector.collected_on_the_event_loop == [False]


def test_without_prometheus_client_nothing_is_registered(monkeypatch):
    monkeypatch.setattr(observability, "PROMETHEUS_AVAILABLE", False)
    collector = Collector()

    assert register_collector(collector.name, collector) is False
    assert collector.name not in observability._COLLECTORS
