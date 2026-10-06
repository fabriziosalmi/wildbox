"""The health body says a status, not what was raised (#755).

``GET /health`` needs no credential. When a check raised, its body named the
class of the exception (``"error": "ValueError"``): a fact about the
service's internals for whoever asks. The cause is in the log, with its
traceback; the body has the status and a fixed word.
"""

import logging
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# conftest.py does the same; repeated so the file reads on its own.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app import main  # noqa: E402

MARKER = "cache-7.internal:6379 said no"


class Raises:
    def __init__(self, error):
        self.error = error

    def ping(self):
        raise self.error


@pytest.fixture
def client():
    return TestClient(main.app, raise_server_exceptions=False)


@pytest.mark.parametrize(
    "error", [ValueError(MARKER), KeyError(MARKER), TypeError(MARKER)], ids=repr
)
def test_a_failed_check_is_a_status_and_not_an_exception_class(
    client, monkeypatch, caplog, error
):
    monkeypatch.setattr(main, "redis_client", Raises(error))

    with caplog.at_level(logging.ERROR):
        response = client.get("/health")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "unhealthy"
    assert body["checks"] == {"api": "unhealthy", "error": "Health check failed"}
    assert type(error).__name__ not in response.text
    assert MARKER not in response.text
    # The operator still has the cause, and where it came from.
    assert type(error).__name__ in caplog.text
    assert MARKER in caplog.text
    assert any(record.exc_info for record in caplog.records)


def test_a_dependency_that_cannot_be_reached_is_degraded_without_its_address(
    client, monkeypatch, caplog
):
    monkeypatch.setattr(main, "redis_client", Raises(ConnectionError(MARKER)))

    with caplog.at_level(logging.ERROR):
        response = client.get("/health")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"] == {
        "api": "degraded",
        "error": "Service connection issue",
    }
    assert MARKER not in response.text
    assert "ConnectionError" not in response.text
    assert MARKER in caplog.text
