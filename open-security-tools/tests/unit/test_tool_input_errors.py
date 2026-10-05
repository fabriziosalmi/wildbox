"""A tool's 422 names the fields that failed validation (#585).

The tool endpoint validates its body against the tool's input model and used
to answer every failure with the bare message "Input validation failed", so a
client could not tell which field to correct. The answer now carries each
error's location, message and type in the canonical error body's
``details.errors``, and still never echoes the submitted values back.

hash_generator is the tool: it touches no network.
"""

import os
import sys
import uuid

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.api import router as router_module  # noqa: E402
from app.auth import verify_api_key  # noqa: E402
from app.tool_loader import load_tool_module  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from open_security_shared.errors import install_error_handlers  # noqa: E402
from open_security_shared.gateway_auth import GatewayUser  # noqa: E402

TOOL = "hash_generator"
SECRET_LOOKING = "do-not-echo-" + uuid.uuid4().hex


@pytest.fixture
def client():
    if not any(
        getattr(r, "path", "") == f"/api/tools/{TOOL}"
        for r in router_module.router.routes
    ):
        router_module.register_tool_endpoint(None, TOOL, load_tool_module(TOOL))
    app = FastAPI()
    install_error_handlers(app)
    app.include_router(router_module.router)
    app.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=str(uuid.uuid4()),
        team_id=str(uuid.uuid4()),
        role="member",
        auth_type="session",
    )
    return TestClient(app, raise_server_exceptions=False)


def test_a_rejected_body_names_each_field_and_why(client):
    response = client.post(
        f"/api/tools/{TOOL}",
        # input_text is required; iterations must be >= 1.
        json={"iterations": 0, "salt": SECRET_LOOKING},
    )

    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["message"] == "Input validation failed"
    errors = {tuple(item["loc"]): item for item in error["details"]["errors"]}
    assert set(errors) == {("input_text",), ("iterations",)}
    assert errors[("input_text",)]["type"] == "missing"
    assert errors[("iterations",)]["type"] == "greater_than_equal"
    assert "greater than or equal to 1" in errors[("iterations",)]["msg"]
    for item in error["details"]["errors"]:
        assert set(item) == {"loc", "msg", "type"}


def test_the_submitted_values_are_not_echoed(client):
    response = client.post(
        f"/api/tools/{TOOL}",
        json={"input_text": SECRET_LOOKING, "iterations": SECRET_LOOKING},
    )

    assert response.status_code == 422, response.text
    assert SECRET_LOOKING not in response.text


def test_a_valid_body_still_runs(client):
    response = client.post(
        f"/api/tools/{TOOL}", json={"input_text": "wildbox", "hash_types": ["sha256"]}
    )

    assert response.status_code == 200, response.text
    assert [h["algorithm"] for h in response.json()["hash_results"]] == ["sha256"]


def test_the_submitted_values_are_not_logged_either(client, caplog):
    # The route logged str() of pydantic's error, which quotes every value
    # that was refused: the secret left the response and stayed in the log.
    with caplog.at_level("DEBUG"):
        response = client.post(
            f"/api/tools/{TOOL}",
            json={"input_text": SECRET_LOOKING, "iterations": SECRET_LOOKING},
        )

    assert response.status_code == 422, response.text
    assert SECRET_LOOKING not in caplog.text
    refusals = [
        record
        for record in caplog.records
        if "Input validation failed" in record.getMessage()
    ]
    assert refusals, "the refusal is still logged"
    for record in refusals:
        assert SECRET_LOOKING not in str(record.__dict__)


def test_the_reduction_is_the_one_every_service_shares():
    # app/api/router.py had a copy of its own (#735). The checks before a
    # run now live in app/prerun.py (#743), for the synchronous route, the
    # asynchronous submission and the task: that is where the shared
    # reduction is used, and the router keeps none.
    from app import prerun
    from app.api import router
    from open_security_shared import errors
    from pydantic import BaseModel, ValidationError

    assert prerun.field_errors is errors.field_errors
    assert not hasattr(router, "field_errors")
    assert not hasattr(router, "input_field_errors")

    class Model(BaseModel):
        port: int

    with pytest.raises(ValidationError) as refused:
        Model(port=SECRET_LOOKING)
    reduced = prerun.input_field_errors(refused.value)
    assert reduced == errors.field_errors(refused.value.errors(include_url=False))
    assert SECRET_LOOKING not in str(reduced)
