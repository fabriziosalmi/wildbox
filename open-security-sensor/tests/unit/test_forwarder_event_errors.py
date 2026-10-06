"""An event the sender cannot make into what it sends is counted, whatever
the error (#765).

The sender expected three errors of an event JSON cannot carry (TypeError,
ValueError, AttributeError) and counted the event under
``events_dropped_unserializable``. Any other error left ``_prepare``: the
event was counted as received and as nothing else, its Delivery was never
settled, so its log file's position stayed before it for as long as the
sensor ran, and the sender's loop logged "Error collecting events" and slept
for a second before taking the next one.

No collector produces such an event today, and the count must not depend on
that. The one used here is real: a value nested deeper than the interpreter
recurses, for which ``json.dumps`` raises RecursionError.
"""

import asyncio
import logging
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.core.config import DataLakeConfig, SensorConfig  # noqa: E402
from sensor.pipeline import data_forwarder  # noqa: E402
from sensor.pipeline.data_forwarder import DataForwarder  # noqa: E402
from sensor.pipeline.delivery import DELIVERY_KEY, Delivery  # noqa: E402

API_KEY = "wsk_t3st.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def _forwarder():
    config = SensorConfig(
        data_lake=DataLakeConfig(
            endpoint="https://gateway.example",
            api_key=API_KEY,
            batch_size=100,
            flush_interval=3600,
        )
    )
    return DataForwarder(config, asyncio.Queue())


def _nested(depth=100_000):
    """A value JSON could carry, were it not nested this deep."""
    value = []
    for _ in range(depth):
        value = [value]
    return value


def _event(name, settled, **data):
    return {
        "type": "log.app",
        "source": "log_forwarder",
        "data": {"raw_message": name, **data},
        DELIVERY_KEY: Delivery(lambda: settled.append(name)),
    }


@pytest.fixture
def no_session(monkeypatch):
    class Session:
        closed = True

        async def close(self):
            pass

    async def session(self):
        self.session = Session()

    monkeypatch.setattr(DataForwarder, "_init_session", session)
    monkeypatch.setattr(data_forwarder, "STOP_FLUSH_SECONDS", 0.2)


def test_the_error_is_one_the_sender_did_not_expect():
    # What makes this event different from one with a NaN or a set in it.
    with pytest.raises(RecursionError):
        data_forwarder.encode_event({"data": _nested()}, "sensor-1")


def test_an_event_that_fails_with_an_unexpected_error_is_counted_and_settled(caplog):
    forwarder = _forwarder()
    settled = []

    with caplog.at_level(logging.ERROR, logger=data_forwarder.__name__):
        # main: RecursionError, out of accept().
        taken = forwarder.accept(_event("nested too deep", settled, value=_nested()))

    assert taken is False
    stats = forwarder.stats
    assert stats["events_received"] == 1
    assert stats["events_dropped_unserializable"] == 1
    assert stats["events_dropped"] == 1
    # Dropped for good: its collector may move past it.
    assert settled == ["nested too deep"]
    assert forwarder.held == 0
    (said,) = [record.getMessage() for record in caplog.records]
    assert said.startswith(
        "Dropped an event of type 'log.app': making it into what is sent "
        "failed with RecursionError: "
    )


@pytest.mark.asyncio
async def test_the_running_sender_counts_it_and_takes_the_next_event_at_once(
    no_session, caplog
):
    forwarder = _forwarder()
    settled = []
    forwarder.input_queue.put_nowait(
        _event("nested too deep", settled, value=_nested())
    )
    forwarder.input_queue.put_nowait(_event("fine", settled))

    await forwarder.start()
    try:
        with caplog.at_level(logging.ERROR, logger=data_forwarder.__name__):
            # Turns of the event loop, not time: main slept a second after
            # the error before it took the second event.
            for _ in range(200):
                await asyncio.sleep(0)
            assert forwarder.stats["events_received"] == 2
            assert len(forwarder.buffer) == 1
            await asyncio.wait_for(forwarder.input_queue.join(), timeout=5)
    finally:
        await forwarder.stop()

    stats = forwarder.stats
    assert stats["events_dropped_unserializable"] == 1
    assert settled == ["nested too deep"]
    assert "Error collecting events" not in caplog.text
    # Every event received is somewhere: sent, dropped, or returned.
    assert stats["events_received"] == (
        stats["events_forwarded"]
        + stats["events_dropped"]
        + stats["events_returned_to_source"]
    )
