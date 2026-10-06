"""A connector logs which parameters a step passes, never their values (#755).

``BaseConnector.execute_action`` logged every parameter of every action,
masking the values of six key names it knew (``api_key``, ``password``,
``secret``, ``token``, ``credential``, ``auth``) and nothing else. A step's
parameters are rendered from the trigger data a caller submits: an
``Authorization`` header passed to an API action, a request body, a target,
a message went to the log as they were.
"""

import logging
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Importing app.config builds Settings(), which requires these.
os.environ.setdefault("SECRET_KEY", "x" * 40)
os.environ.setdefault("GATEWAY_INTERNAL_SECRET", "y" * 40)

from app.connectors.base import BaseConnector, ConnectorError  # noqa: E402

SECRET = "do-not-log-" + uuid.uuid4().hex


class Probe(BaseConnector):
    def get_available_actions(self):
        return {"call": "Call something", "fail": "Fail on its input"}

    def call(self, **params):
        return {"received": sorted(params)}

    def fail(self, **params):
        raise ValueError(f"cannot use {params['target']}")


@pytest.fixture
def connector():
    return Probe("probe", {})


def test_the_names_of_a_steps_parameters_are_logged_and_no_value(connector, caplog):
    params = {
        "url": f"https://api.example.com/v1?key={SECRET}",
        "headers": {"Authorization": f"Bearer {SECRET}"},
        "authorization": SECRET,  # not one of the six names that were masked
        "body": {"note": SECRET},
        "token": SECRET,  # one that was
    }

    with caplog.at_level(logging.DEBUG):
        result = connector.execute_action("call", params)

    assert result == {"received": sorted(params)}
    assert SECRET not in caplog.text
    for record in caplog.records:
        assert SECRET not in str(record.__dict__)
    assert (
        "Executing action 'call' with parameters: "
        "['authorization', 'body', 'headers', 'token', 'url']"
    ) in caplog.text


def test_a_failed_action_is_logged_by_class_and_reported_to_the_run(connector, caplog):
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ConnectorError) as failed:
            connector.execute_action("fail", {"target": SECRET})

    # The run's caller reads why the step failed; the log has the class.
    assert SECRET in str(failed.value)
    assert SECRET not in caplog.text
    assert "Action 'fail' failed: ValueError" in caplog.text


WORKER_START = """
import logging
import app.workflow_engine  # what `python -m dramatiq app.workflow_engine` imports
logging.getLogger().setLevel(logging.DEBUG)
print(*(logging.getLogger(n).getEffectiveLevel() for n in ("httpx", "httpcore")))
"""


def test_the_worker_does_not_let_httpx_log_the_urls_the_connectors_call(tmp_path):
    """httpx: 'HTTP Request: GET http://data/...?q=<what the step asked>' at INFO."""
    result = subprocess.run(
        [sys.executable, "-c", WORKER_START],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
            "SECRET_KEY": "x" * 40,
            "GATEWAY_INTERNAL_SECRET": "y" * 40,
            "ENVIRONMENT": "development",
        },
        timeout=180,
    )

    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.split()[-2:] == [str(logging.WARNING)] * 2
