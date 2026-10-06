"""No event is out of sight between two stages when the sensor stops (#754).

``test_what_was_collected_just_before_the_stop_still_reaches_the_gateway``
failed about once in fifty runs (3 of 80 when it was found, 2 of 150 when it
was traced): the ninth of nine events never reached the gateway. The worker
took an event with ``asyncio.wait_for(queue.get())`` and counted it as in
flight when it resumed. On Python 3.11, which the image and the CI run,
``wait_for`` runs the ``get`` in a task of its own: the event left the queue
in one turn of the event loop and the worker resumed two turns later. A drain
that looked in between saw two empty queues and nothing in flight, and
stopped the pipeline; the worker then put the event on a queue nobody read
any more.

The tests here do not wait for that to happen. They make the drain look at
the moment the event leaves the queue, and one, two... turns of the loop
later, and they hold the event in the worker's hands for as long as they
want. The agent, its queues, its processor and its sender are the real ones;
the gateway is a stand-in at the sender's ``_send``.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.core import agent as agent_module  # noqa: E402
from sensor.core.agent import CountingQueue, SecuritySensorAgent  # noqa: E402
from sensor.core.config import (  # noqa: E402
    CollectionConfig,
    DataLakeConfig,
    FIMConfig,
    NetworkConfig,
    PerformanceConfig,
    SensorConfig,
)
from sensor.pipeline import data_forwarder  # noqa: E402
from sensor.pipeline.data_forwarder import RETRY, SENT, DataForwarder  # noqa: E402
from sensor.pipeline.data_processor import DataProcessor  # noqa: E402
from sensor.pipeline.delivery import DELIVERY_KEY, Delivery  # noqa: E402

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Turns of the event loop after an event left a queue at which the drain is
# made to look. On main the first two found nothing left.
TURNS = range(6)
# Far more turns than any hand-off takes: a drain that has not ended after
# these is waiting for the event, not on its way to ending.
MANY_TURNS = 200


class Gateway:
    """What the sender's requests are answered, and the lines accepted."""

    def __init__(self):
        self.answer = SENT
        self.accepted = []


@pytest.fixture
def gateway(monkeypatch):
    gateway = Gateway()

    class Session:
        closed = False

        async def close(self):
            self.closed = True

    async def session(self):
        self.session = Session()

    async def send(self, body):
        if gateway.answer == SENT:
            gateway.accepted.extend(
                event["event_data"]["data"]["raw_message"]
                for event in json.loads(body)["events"]
            )
        return gateway.answer

    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(DataForwarder, "_send", send)
    return gateway


def _agent(workers=4, **data_lake):
    """An agent with no collector: the tests put the events themselves."""
    settings = {"api_key": API_KEY, "batch_size": 100, "flush_interval": 3600}
    settings.update(data_lake)
    return SecuritySensorAgent(
        SensorConfig(
            data_lake=DataLakeConfig(endpoint="https://gateway.example", **settings),
            collection=CollectionConfig(
                process_events=False,
                network_connections=False,
                file_monitoring=False,
                user_events=False,
                system_inventory=False,
                log_forwarding=False,
            ),
            fim=FIMConfig(enabled=False),
            network=NetworkConfig(enable_api=False),
            performance=PerformanceConfig(worker_threads=workers),
        )
    )


def _event(message, **extra):
    """An event as a collector would queue it."""
    event = {"type": "file_created", "source": "fim", "data": {"raw_message": message}}
    event.update(extra)
    return event


async def _stop(agent):
    """Stop the agent; a stop that does not end fails the test instead of
    holding the whole run."""
    await asyncio.wait_for(agent.stop(), timeout=30)


async def _turns(count=MANY_TURNS):
    for _ in range(count):
        await asyncio.sleep(0)


async def _until(condition, timeout=10):
    deadline = asyncio.get_running_loop().time() + timeout
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.005)


class Watched(CountingQueue):
    """A queue that says when an item leaves it: ``taken(item)`` is called
    at that very moment, before whoever asked for the item has it."""

    taken = None

    def _get(self):
        item = super()._get()
        if self.taken is not None:
            self.taken(item)
        return item


def _when_taken(queue, turns, begin):
    """Start ``begin()`` as a task ``turns`` turns of the loop after the
    first item leaves ``queue``; the list that task is added to."""
    loop = asyncio.get_running_loop()
    started = []

    def look(left):
        if left:
            loop.call_soon(look, left - 1)
        else:
            started.append(loop.create_task(begin()))

    def taken(item):
        queue.taken = None
        look(turns)

    queue.taken = taken
    return started


@pytest.fixture
def held(monkeypatch):
    """The workers hold every event they take until ``held.set()``."""
    gate = asyncio.Event()
    process = DataProcessor._process_single_event

    async def hold(self, event):
        await gate.wait()
        return await process(self, event)

    monkeypatch.setattr(DataProcessor, "_process_single_event", hold)
    return gate


# -- from the collectors' queue to the processor ----------------------------


@pytest.mark.parametrize("turns", TURNS)
@pytest.mark.asyncio
async def test_the_drain_waits_for_an_event_from_the_moment_it_leaves_the_queue(
    gateway, held, monkeypatch, turns
):
    # Long enough that the drain cannot end by its deadline in this test.
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 60)
    agent = _agent()
    agent.event_queue = Watched(maxsize=10)

    await agent.start()
    try:
        await _turns()  # the workers are waiting for an event
        drains = _when_taken(agent.event_queue, turns, agent._drain_queues)
        agent.event_queue.put_nowait(_event("the last event"))
        await _until(lambda: drains)
        (drain,) = drains

        # The event has left the queue and no worker has passed it on. main,
        # turns 0 and 1: the drain had ended, with the event still to come.
        await _turns()
        assert not drain.done()
        assert agent.processed_queue.empty() and not agent.data_forwarder.buffer

        held.set()
        await asyncio.wait_for(drain, timeout=5)
        # Ended, and the event is where the sender's last batches take it.
        assert len(agent.data_forwarder.buffer) == 1
    finally:
        held.set()
        await _stop(agent)

    assert gateway.accepted == ["the last event"]
    assert agent.data_forwarder.stats["events_forwarded"] == 1


@pytest.mark.parametrize("turns", TURNS)
@pytest.mark.asyncio
async def test_the_stop_delivers_an_event_a_worker_had_just_taken(
    gateway, monkeypatch, turns
):
    # The whole stop, begun in the window: nothing holds the event here but
    # the hand-off itself.
    agent = _agent()
    agent.event_queue = Watched(maxsize=10)

    await agent.start()
    # Nothing to stop before the drain: it begins in the stop's first turn.
    await agent.resource_monitor.stop()
    agent.resource_monitor = None
    await _turns()
    stops = _when_taken(agent.event_queue, turns, agent._stop_components)
    agent.event_queue.put_nowait(_event("the last event"))
    await _until(lambda: stops)
    await asyncio.wait_for(stops[0], timeout=10)
    await _turns()

    assert gateway.accepted == ["the last event"]
    assert agent.event_queue.empty() and agent.processed_queue.empty()
    assert agent.data_processor.in_flight == 0


# -- from the processor's queue to the sender --------------------------------


@pytest.mark.parametrize("turns", TURNS)
@pytest.mark.asyncio
async def test_an_event_that_left_the_processed_queue_is_the_senders(
    gateway, monkeypatch, turns
):
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 60)
    agent = _agent()
    agent.processed_queue = Watched(maxsize=10)

    await agent.start()
    try:
        await _turns()
        drains = _when_taken(agent.processed_queue, turns, agent._drain_queues)
        agent.event_queue.put_nowait(_event("the last event"))
        await _until(lambda: drains)
        await asyncio.wait_for(drains[0], timeout=5)
        # Whenever the drain looked, it ended with the event in the buffer.
        assert len(agent.data_forwarder.buffer) == 1
        assert agent.data_forwarder.stats["events_received"] == 1
    finally:
        await _stop(agent)

    assert gateway.accepted == ["the last event"]


@pytest.mark.asyncio
async def test_an_event_waiting_for_room_in_the_buffer_does_not_hold_the_drain(
    gateway, monkeypatch
):
    # In the sender's hand, with the buffer full: it has reached the sender,
    # whose stop takes it. Waiting for it would be waiting for the gateway.
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 60)
    monkeypatch.setattr(data_forwarder, "STOP_FLUSH_SECONDS", 0.5)
    gateway.answer = RETRY
    agent = _agent(batch_size=2, buffer_max_events=2)

    await agent.start()
    agent.data_forwarder.min_request_interval = 0.002
    for message in ("in the buffer", "in the buffer too", "in hand"):
        agent.event_queue.put_nowait(_event(message))
    await _until(lambda: agent.data_forwarder.get_status()["buffer"]["full"])
    await asyncio.wait_for(agent._drain_queues(), timeout=5)
    # Counted where it is: main counted the buffer's two.
    assert agent.get_stats()["events_in_pipeline"] == 3
    await _stop(agent)

    stats = agent.data_forwarder.stats
    assert stats["events_received"] == 3
    assert stats["events_dropped_shutdown"] == 3
    assert agent.get_stats()["events_in_pipeline"] == 0


@pytest.mark.asyncio
async def test_the_drain_waits_for_what_is_on_the_processed_queue(
    gateway, held, monkeypatch
):
    # The second queue is asked too, and after the first: an event the
    # processor has passed on is not the sender's until the sender has it.
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 60)
    monkeypatch.setattr(data_forwarder, "STOP_FLUSH_SECONDS", 0.5)
    gateway.answer = RETRY
    agent = _agent(workers=1, batch_size=2, buffer_max_events=2)

    await agent.start()
    agent.data_forwarder.min_request_interval = 0.002
    held.set()
    for message in ("in the buffer", "in the buffer too", "in hand"):
        agent.event_queue.put_nowait(_event(message))
    await _until(lambda: agent.data_forwarder.get_status()["buffer"]["full"])
    # One more, which the worker holds while the drain begins.
    held.clear()
    agent.event_queue.put_nowait(_event("behind them"))
    await _until(lambda: agent.data_processor.in_flight == 1)
    drain = asyncio.create_task(agent._drain_queues())
    await _turns()
    assert not drain.done()

    # Passed on, to a sender that takes nothing: on the queue it stays, and
    # the drain goes on waiting, until its deadline.
    held.set()
    await _until(lambda: agent.processed_queue.qsize() == 1)
    await _turns()
    assert not drain.done()

    drain.cancel()
    await asyncio.gather(drain, return_exceptions=True)
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 0.1)
    await _stop(agent)
    assert agent.data_forwarder.stats["events_dropped_shutdown"] == 3
    assert agent.event_queue.empty() and agent.processed_queue.empty()


@pytest.mark.asyncio
async def test_an_event_that_fails_in_the_senders_hands_is_finished_with(
    gateway, monkeypatch
):
    # Whatever happens to an event once it is taken, the queue is told: a
    # count that stayed one too high would make every stop wait for its
    # deadline.
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 60)
    prepare = DataForwarder._prepare

    def failing(self, event):
        if event["data"]["raw_message"] == "bad":
            raise RuntimeError("not an event")
        return prepare(self, event)

    monkeypatch.setattr(DataForwarder, "_prepare", failing)
    agent = _agent()

    await agent.start()
    try:
        agent.event_queue.put_nowait(_event("bad"))
        agent.event_queue.put_nowait(_event("good"))
        await asyncio.wait_for(agent._drain_queues(), timeout=10)
        assert len(agent.data_forwarder.buffer) == 1
    finally:
        await _stop(agent)

    assert gateway.accepted == ["good"]


@pytest.mark.asyncio
async def test_an_event_the_sender_drops_does_not_hold_the_drain(gateway, monkeypatch):
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 60)
    agent = _agent()

    await agent.start()
    try:
        # NaN: JSON cannot carry it.
        unsendable = _event("dropped")
        unsendable["data"]["value"] = float("nan")
        agent.event_queue.put_nowait(unsendable)
        agent.event_queue.put_nowait(_event("kept"))
        await asyncio.wait_for(agent._drain_queues(), timeout=5)
        assert agent.data_forwarder.stats["events_dropped_unserializable"] == 1
        assert len(agent.data_forwarder.buffer) == 1
    finally:
        await _stop(agent)

    assert gateway.accepted == ["kept"]


# -- what the drain's deadline leaves behind ---------------------------------


@pytest.mark.asyncio
async def test_events_in_the_workers_hands_at_the_deadline_are_counted_and_said(
    gateway, held, monkeypatch, caplog
):
    # main: the stop said nothing of them, and each worker put its event on
    # the processed queue afterwards, where it stayed.
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 0.1)
    agent = _agent(workers=2)
    settled = []

    await agent.start()
    line = _event("a line of a log")
    line[DELIVERY_KEY] = Delivery(lambda: settled.append("line"), replayable=True)
    agent.event_queue.put_nowait(line)
    agent.event_queue.put_nowait(_event("a change"))
    agent.event_queue.put_nowait(_event("still queued"))
    await _until(lambda: agent.data_processor.in_flight == 2)
    assert agent.get_stats()["events_in_pipeline"] == 3
    with caplog.at_level(logging.WARNING):
        await _stop(agent)

    assert (
        "Stopped with 3 events still on their way to the sender: 2 are "
        "dropped, 1 will be read again from their log source after the restart"
    ) in caplog.text
    # The workers have ended, and with them what they held.
    held.set()
    await _turns()
    assert agent.data_processor.in_flight == 0
    assert agent.event_queue.empty() and agent.processed_queue.empty()
    # Not delivered and not dropped for good: the line is read again.
    assert settled == [] and gateway.accepted == []
    assert agent.data_processor.stats["events_processed"] == 0


@pytest.mark.asyncio
async def test_a_worker_waiting_for_room_downstream_is_stopped_with_its_event(
    gateway, monkeypatch, caplog
):
    # The gateway takes nothing and everything is full: the buffer, the
    # sender's hand, the processed queue, and a worker waiting to put.
    monkeypatch.setattr(agent_module, "QUEUE_DRAIN_SECONDS", 0.1)
    monkeypatch.setattr(data_forwarder, "STOP_FLUSH_SECONDS", 0.5)
    gateway.answer = RETRY
    agent = _agent(workers=1, batch_size=2, buffer_max_events=2)
    agent.processed_queue = asyncio.Queue(maxsize=1)

    await agent.start()
    agent.data_forwarder.min_request_interval = 0.002
    for index in range(6):
        agent.event_queue.put_nowait(_event(f"event {index}"))
    await _until(lambda: agent.data_processor.in_flight == 1)
    await _until(lambda: agent.processed_queue.full())
    await _turns()
    with caplog.at_level(logging.WARNING):
        await _stop(agent)
    await _turns()

    # Three reached the sender: two in its buffer, one in its hand. One on
    # the processed queue, one in the worker's hand and one never taken did
    # not. main said two, and the worker's stayed on the processed queue.
    assert agent.data_forwarder.stats["events_dropped_shutdown"] == 3
    assert (
        "Stopped with 3 events still on their way to the sender: 3 are dropped"
    ) in caplog.text
    assert agent.event_queue.empty() and agent.processed_queue.empty()
    assert agent.data_processor.in_flight == 0
    # Every event is accounted for, so neither queue has one unfinished: a
    # second stop would not wait for them.
    await asyncio.wait_for(agent._handed_over(), timeout=1)


# -- the processor by itself ---------------------------------------------------


def _processor(workers=2):
    config = SensorConfig(
        data_lake=DataLakeConfig(endpoint="https://gateway.example", api_key=""),
        performance=PerformanceConfig(worker_threads=workers),
    )
    return DataProcessor(config, asyncio.Queue(), asyncio.Queue())


@pytest.mark.asyncio
async def test_the_processor_finishes_with_every_event_it_takes():
    # join() returns when every event put was passed on or filtered: that is
    # what the drain waits on.
    processor = _processor()
    for index in range(5):
        processor.input_queue.put_nowait(_event(f"event {index}"))
    processor.input_queue.put_nowait(_event("filtered", data={}))

    await processor.start()
    try:
        await asyncio.wait_for(processor.input_queue.join(), timeout=5)
        assert processor.output_queue.qsize() == 5
        assert processor.stats["events_processed"] == 5
        assert processor.stats["events_filtered"] == 1
        assert processor.in_flight == 0
    finally:
        await processor.stop()


@pytest.mark.asyncio
async def test_stopping_the_processor_ends_its_workers():
    # main: they went on for up to a second each, in a wait_for nobody
    # cancelled, and were destroyed pending with the event loop.
    before = asyncio.all_tasks()
    processor = _processor(workers=3)

    await processor.start()
    await _turns()
    workers = asyncio.all_tasks() - before
    assert len(workers) == 3
    await processor.stop()

    assert all(worker.done() for worker in workers)
    assert processor.interrupted == []


@pytest.mark.asyncio
async def test_an_event_that_fails_in_a_worker_is_counted_settled_and_not_the_last(
    monkeypatch, caplog
):
    # main: the error was counted and the event's Delivery forgotten, so
    # the position of its log file never moved past it.
    processor = _processor(workers=1)
    settled = []

    def attach(event, delivery):
        if event["data"]["raw_message"] == "bad":
            raise RuntimeError("no room for that")

    monkeypatch.setattr("sensor.pipeline.data_processor.attach_delivery", attach)
    bad = _event("bad")
    bad[DELIVERY_KEY] = Delivery(lambda: settled.append("bad"))
    processor.input_queue.put_nowait(bad)
    processor.input_queue.put_nowait(_event("good"))

    await processor.start()
    try:
        with caplog.at_level(logging.ERROR):
            await asyncio.wait_for(processor.input_queue.join(), timeout=5)
    finally:
        await processor.stop()

    assert processor.stats["errors"] == 1
    assert processor.stats["events_processed"] == 1
    assert settled == ["bad"]
    assert processor.output_queue.qsize() == 1
    assert "no room for that" in caplog.text
