"""hash_generator's schema offers only the algorithms it implements (#611).

The input model defaulted ``hash_types`` to md5, sha1, sha256 and sha512 while
the generator no longer implemented md5 or sha1, so a run with the defaults,
and the form the dashboard builds from the schema, answered
``success: false``. The algorithms are now an enum built from the generator's
own table: the defaults run, and an unsupported algorithm is a 422 before the
tool runs.
"""

import asyncio
import hashlib
import os
import sys
import uuid

import pytest

os.environ.setdefault("API_KEY", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.api import router as router_module  # noqa: E402
from app.auth import verify_api_key  # noqa: E402
from app.tool_loader import load_tool_module  # noqa: E402
from app.tools.hash_generator.main import HashGenerator, execute_tool  # noqa: E402
from app.tools.hash_generator.schemas import HashGeneratorInput  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from open_security_shared.gateway_auth import GatewayUser  # noqa: E402
from pydantic import ValidationError  # noqa: E402

TOOL = "hash_generator"


@pytest.fixture
def client():
    if not any(
        getattr(r, "path", "") == f"/api/tools/{TOOL}"
        for r in router_module.router.routes
    ):
        router_module.register_tool_endpoint(None, TOOL, load_tool_module(TOOL))
    router_module.DISCOVERED_TOOLS.setdefault(TOOL, load_tool_module(TOOL))
    app = FastAPI()
    app.include_router(router_module.router)
    app.dependency_overrides[verify_api_key] = lambda: GatewayUser(
        user_id=str(uuid.uuid4()), team_id=str(uuid.uuid4()), role="member"
    )
    return TestClient(app, raise_server_exceptions=False)


def _hash_types_schema(schema):
    items = schema["properties"]["hash_types"]["items"]
    if "$ref" in items:
        items = schema["$defs"][items["$ref"].rsplit("/", 1)[-1]]
    return schema["properties"]["hash_types"], items


def test_the_schema_enum_is_the_supported_algorithms():
    field, items = _hash_types_schema(HashGeneratorInput.model_json_schema())
    assert items["enum"] == list(HashGenerator.SUPPORTED_ALGORITHMS)
    assert set(field["default"]) <= set(HashGenerator.SUPPORTED_ALGORITHMS)
    assert field["default"] == ["sha256", "sha512"]
    for removed in ("md5", "sha1"):
        assert removed not in field["description"]


def test_the_published_schema_is_the_validated_one(client):
    response = client.get(f"/api/tools/{TOOL}/info")
    assert response.status_code == 200, response.text
    _, items = _hash_types_schema(response.json()["input_schema"])
    assert items["enum"] == list(HashGenerator.SUPPORTED_ALGORITHMS)


def test_the_defaults_run():
    result = asyncio.run(execute_tool(HashGeneratorInput(input_text="wildbox")))

    assert result.success, result.error
    assert [(h.algorithm, h.hash_value) for h in result.hash_results] == [
        ("sha256", hashlib.sha256(b"wildbox").hexdigest()),
        ("sha512", hashlib.sha512(b"wildbox").hexdigest()),
    ]


def test_the_defaults_run_through_the_endpoint(client):
    response = client.post(f"/api/tools/{TOOL}", json={"input_text": "wildbox"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True, body
    assert [h["algorithm"] for h in body["hash_results"]] == ["sha256", "sha512"]


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "SHA256", "whirlpool"])
def test_an_unsupported_algorithm_is_refused_by_the_model(algorithm):
    with pytest.raises(ValidationError):
        HashGeneratorInput(input_text="wildbox", hash_types=["sha256", algorithm])


def test_md5_is_a_422_not_a_failed_run(client):
    response = client.post(
        f"/api/tools/{TOOL}", json={"input_text": "wildbox", "hash_types": ["md5"]}
    )

    assert response.status_code == 422, response.text


def test_an_empty_list_is_refused():
    with pytest.raises(ValidationError):
        HashGeneratorInput(input_text="wildbox", hash_types=[])


def test_output_format_is_an_enum():
    with pytest.raises(ValidationError):
        HashGeneratorInput(input_text="wildbox", output_format="binary")


@pytest.mark.parametrize("algorithm", list(HashGenerator.SUPPORTED_ALGORITHMS))
def test_a_salted_hash_uses_the_algorithm_it_is_labelled_with(algorithm):
    params = HashGeneratorInput(
        input_text="wildbox",
        hash_types=[algorithm],
        include_salted=True,
        salt="pepper",
        iterations=3,
    )
    result = asyncio.run(execute_tool(params))

    assert result.success, result.error
    (only,) = result.hash_results
    assert only.algorithm == f"{algorithm}_pbkdf2"
    expected = hashlib.pbkdf2_hmac(algorithm, b"wildbox", b"pepper", 3).hex()
    assert only.hash_value == expected
