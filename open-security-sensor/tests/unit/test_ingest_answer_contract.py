"""The forwarder reads each answer of the data service's ingest as that service means it (#755).

``tests/shared/ingest_answer_vectors.json`` lists what ``POST /api/v1/ingest``
answers: a batch stored whole, an event the schema refuses, a value the
database refuses, too many events, a database that did not take the batch,
a fault of the service. The data service's tests provoke each case and
compare its status and body with the file; these give the same status and
body to the forwarder and check what it does with the batch:

* ``sent``: the events leave the buffer as delivered;
* ``refused``: the batch is at fault. It is split in halves until the event
  the data service refuses is alone, and that one is dropped;
* ``retry``: nothing is wrong with the batch. It is kept whole and sent
  again, for as long as it takes.

The answer that started this was none of them: a 200 with
``events_ingested: 0`` for a batch whose commit had failed. The forwarder
reads that as a refusal, and split and dropped events over a fault of the
service. The data service no longer gives it; a service fault is a 5xx.
"""

import json
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

from sensor.pipeline.data_forwarder import (  # noqa: E402
    OK,
    PAYLOAD,
    REFUSED,
    RETRY,
    SENT,
    UNAVAILABLE,
    classify_answer,
    stored_events,
)

REPO_ROOT = SERVICE_ROOT.parent
ANSWERS = json.loads(
    (REPO_ROOT / "tests" / "shared" / "ingest_answer_vectors.json").read_text()
)["answers"]
OUTCOMES = {"sent": SENT, "refused": REFUSED, "retry": RETRY}
STATES = {"ok": OK, "payload": PAYLOAD, "unavailable": UNAVAILABLE}


@pytest.mark.parametrize("answer", ANSWERS, ids=lambda answer: answer["case"])
def test_the_forwarder_does_what_the_answer_means(answer):
    text = json.dumps(answer["body"])

    outcome, state, reason = classify_answer(answer["status"], text)

    assert outcome == OUTCOMES[answer["sensor"]["outcome"]]
    assert state == STATES[answer["sensor"]["state"]]
    assert reason.startswith(f"HTTP {answer['status']}")
    if outcome == SENT:
        assert stored_events(text, answer["events"]) == answer["sensor"]["stored"]
        assert answer["sensor"]["stored"] == answer["events"]


def test_a_refusal_says_why_in_the_sensors_own_log_line():
    by_case = {answer["case"]: answer for answer in ANSWERS}

    refused = by_case["value_not_storable"]
    reason = classify_answer(refused["status"], json.dumps(refused["body"]))[2]

    # The code and the sentence of the data service's answer.
    assert reason == (
        "HTTP 422 BATCH_NOT_STORABLE: The batch holds a value that cannot be "
        "stored; none of its events was stored."
    )


def test_every_outcome_the_forwarder_has_is_one_the_data_service_asks_for():
    asked = {answer["sensor"]["outcome"] for answer in ANSWERS}

    assert asked == set(OUTCOMES)
    # Only the payload costs events: every refusal is a 4xx about the batch.
    for answer in ANSWERS:
        if answer["sensor"]["outcome"] == "refused":
            assert answer["status"] in (400, 413, 422), answer["case"]
        if answer["sensor"]["outcome"] == "retry":
            assert answer["status"] >= 500, answer["case"]


def test_the_data_service_never_answers_200_for_less_than_the_batch():
    """What the forwarder would do with it, kept for a data service of an older release."""
    stored = [a for a in ANSWERS if a["status"] == 200]

    assert [a["body"]["events_ingested"] for a in stored] == [
        a["body"]["events_received"] for a in stored
    ]
    # An older data service's 200 with nothing stored is still not a delivery.
    assert stored_events('{"events_ingested": 0}', 3) == 0
