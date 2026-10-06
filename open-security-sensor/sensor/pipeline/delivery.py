"""What became of an event, told to the collector that produced it.

A collector that can read its source again from a position (a log file, the
journal, an event log) must not move that position past an event the data
service has not taken: a sensor that stops, or is killed, would lose it. Such
a collector puts a ``Delivery`` on the event under ``DELIVERY_KEY``. The
pipeline carries it, never sends it, and settles it exactly when the sensor
has finished with the event:

* the gateway accepted the batch the event was in;
* or the event was dropped for good, and counted: filtered by the processor,
  refused by the gateway with its batch, impossible to serialize, too large,
  or collected while no API key is configured.

An event still in the sensor when it stops is not settled: its collector
reads it again after the restart.
"""

import logging
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

# The key of an event that holds its Delivery. It is removed before the event
# is processed or serialized.
DELIVERY_KEY = "_delivery"


class Delivery:
    """Called once, when the sensor has finished with an event."""

    __slots__ = ("_done", "replayable")

    def __init__(self, done: Callable[[], None], replayable: bool = True):
        self._done: Optional[Callable[[], None]] = done
        # Will the collector read the event again after a restart, if it is
        # not settled? Only if its position outlives the process.
        self.replayable = replayable

    def settle(self) -> None:
        done, self._done = self._done, None
        if done is None:
            return
        try:
            done()
        except Exception:
            # A collector's bookkeeping must not stop the pipeline.
            logger.exception("Error recording what became of an event")


def take_delivery(event: Any) -> Optional[Delivery]:
    """Remove and return the event's Delivery, if it carries one."""
    if not isinstance(event, dict):
        return None
    delivery = event.pop(DELIVERY_KEY, None)
    return delivery if isinstance(delivery, Delivery) else None


def attach_delivery(event: Dict[str, Any], delivery: Optional[Delivery]) -> None:
    if delivery is not None:
        event[DELIVERY_KEY] = delivery


def settle(delivery: Optional[Delivery]) -> None:
    if delivery is not None:
        delivery.settle()
