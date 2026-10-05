"""The models' examples reach the OpenAPI schema, and no pydantic v1 form
is left in the service (#727).

``class Config: schema_extra`` is the pydantic v1 way to attach an example.
Pydantic v2 warns that the key was renamed and ignores it, so none of the
four examples in app/schemas.py was in the schema ``/docs`` renders. The
settings named their variables with ``Field(env=...)``, which v2 ignores as
well; the request models were dumped with ``.dict()`` and the task ID was
checked with ``regex=``, both deprecated.

The examples are also checked against their own models: one that the API
could not answer, or would refuse, is not an example.
"""

import os
import re
import subprocess
import sys
import warnings

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pydantic.warnings import PydanticDeprecationWarning

SERVICE_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, SERVICE_ROOT)

from app import main, schemas  # noqa: E402
from app.config import Settings  # noqa: E402

SECRET = "gateway-secret-for-tests"
HEADERS = {
    "X-Wildbox-User-ID": "7d6c2c1e-1b0a-4a51-9a59-6f0c3b1e2a77",
    "X-Wildbox-Team-ID": "3f1e9b2a-5c4d-4e6f-8a7b-9c0d1e2f3a4b",
    "X-Wildbox-Role": "member",
    "X-Gateway-Secret": SECRET,
}
MODELS = {
    "IOCInput": schemas.IOCInput,
    "AnalysisTaskRequest": schemas.AnalysisTaskRequest,
    "AnalysisTaskStatus": schemas.AnalysisTaskStatus,
    "AnalysisResult": schemas.AnalysisResult,
}


@pytest.fixture(scope="module")
def openapi():
    return main.app.openapi()


# --- The examples ------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(MODELS))
def test_the_example_is_in_the_openapi_schema(openapi, name):
    """The acceptance test of the issue, for each model that has one."""
    assert name in openapi["components"]["schemas"], f"{name} is not in the schema"
    example = openapi["components"]["schemas"][name].get("example")
    assert example, f"{name} has no example in the OpenAPI schema"
    assert example == MODELS[name].model_config["json_schema_extra"]["example"]


@pytest.mark.parametrize("name", sorted(MODELS))
def test_the_example_is_valid_for_its_own_model(name):
    model = MODELS[name]
    example = model.model_config["json_schema_extra"]["example"]

    parsed = model(**example)

    # Every key of the example is a field: a key the model does not have
    # would be dropped in silence and the example would show a field that
    # the API never answers.
    assert set(example) <= set(model.model_fields)
    assert parsed.model_dump(mode="json", exclude_unset=True).keys() == example.keys()


def test_the_task_example_is_a_task_the_read_could_answer(openapi):
    """Its ID is one the route accepts, and its result_url the one the API
    builds: the example had "abc-123-def", which the route refuses."""
    example = schemas.AnalysisTaskStatus.model_config["json_schema_extra"]["example"]
    task_id = next(
        parameter
        for parameter in openapi["paths"]["/v1/analyze/{task_id}"]["get"]["parameters"]
        if parameter["name"] == "task_id"
    )

    assert re.fullmatch(task_id["schema"]["pattern"], example["task_id"])
    assert example["result_url"] == main.RESULT_PATH.format(task_id=example["task_id"])


@pytest.mark.parametrize(
    "task_id", ["abc-123-def", "550E8400-E29B-41D4-A716-446655440000", "1"]
)
def test_a_task_id_that_is_not_a_lowercase_uuid_is_still_refused(monkeypatch, task_id):
    """The pattern, now declared with ``pattern=``, checks what it did."""
    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    client = TestClient(main.app)
    assert client.get(f"/v1/analyze/{task_id}", headers=HEADERS).status_code == 422
    assert client.delete(f"/v1/analyze/{task_id}", headers=HEADERS).status_code == 422


def test_both_answers_of_the_read_are_in_the_schema(openapi):
    """The result was not: the route declared no response model."""
    answer = openapi["paths"]["/v1/analyze/{task_id}"]["get"]["responses"]["200"]
    refs = {
        option["$ref"].rsplit("/", 1)[-1]
        for option in answer["content"]["application/json"]["schema"]["anyOf"]
    }
    assert refs == {"AnalysisResult", "AnalysisTaskStatus"}


# --- The validator, in its v2 form -------------------------------------------


@pytest.mark.parametrize(
    "ioc_type, value",
    [
        ("ipv4", "203.0.113.10"),
        ("domain", "suspicious.example.com"),
        ("sha256", "a" * 64),
        ("email", "someone@example.com"),
    ],
)
def test_a_value_of_its_type_is_accepted(ioc_type, value):
    assert schemas.IOCInput(type=ioc_type, value=value).value == value


@pytest.mark.parametrize(
    "ioc_type, value",
    [
        ("ipv4", "example.com"),
        ("domain", "203.0.113.10"),
        ("sha256", "a" * 63),
        ("md5", "A" * 32),
        ("email", "not an address"),
    ],
)
def test_a_value_that_is_not_of_its_type_is_refused(ioc_type, value):
    """The check reads the type from the fields validated before it."""
    with pytest.raises(ValidationError, match=f"Invalid format for {ioc_type} IOC"):
        schemas.IOCInput(type=ioc_type, value=value)


def test_an_unknown_type_is_refused_for_the_type():
    with pytest.raises(ValidationError) as refused:
        schemas.IOCInput(type="hostname", value="example.com")
    assert [error["loc"] for error in refused.value.errors()] == [("type",)]


# --- The settings: each variable is read by its field's name -----------------


@pytest.mark.parametrize(
    "variable, value",
    [
        ("REDIS_URL", "redis://redis.internal:6379/4"),
        ("CELERY_BROKER_URL", "redis://redis.internal:6379/5"),
        ("CELERY_RESULT_BACKEND", "redis://redis.internal:6379/6"),
        ("GATEWAY_INTERNAL_SECRET", "a-secret-for-this-test"),
        ("INTERNAL_API_KEY", "no-longer-read"),
    ],
)
def test_the_variable_sets_the_field(monkeypatch, variable, value):
    """These five declared ``env=``; they are read by name, as all are."""
    monkeypatch.setenv(variable, value)
    assert getattr(Settings(_env_file=None), variable.lower()) == value


def test_the_settings_still_read_an_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("REDIS_URL=redis://from-the-file:6379/0\n")

    assert Settings.model_config["env_file"] == ".env"
    assert Settings(_env_file=str(env_file)).redis_url == "redis://from-the-file:6379/0"


# --- No v1 form left ---------------------------------------------------------

# Each runs in a process of its own: the warnings are emitted when a class
# is created, once, at import.
NO_V1_FORM = {
    # class Config, schema_extra, @validator, Field(env=...): pydantic says
    # so when it builds the class.
    "models-and-settings": """
import warnings
from pydantic.warnings import PydanticDeprecationWarning
warnings.filterwarnings("error", category=PydanticDeprecationWarning)
warnings.filterwarnings("error", message=".*Valid config keys have changed.*")
import app.schemas, app.config
""",
    # Path(regex=...): FastAPI says so when the route is declared. The
    # shared package is not this service's to change, so pydantic's own
    # warnings are not errors here.
    "routes": """
import warnings
warnings.filterwarnings("error", message=".*regex.*deprecated.*")
import app.main
""",
}


@pytest.mark.parametrize("what", sorted(NO_V1_FORM))
def test_importing_the_service_warns_of_no_v1_form(what):
    env = dict(os.environ, GATEWAY_INTERNAL_SECRET=SECRET)
    result = subprocess.run(
        [sys.executable, "-c", NO_V1_FORM[what]],
        cwd=SERVICE_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]


def test_a_submission_uses_no_deprecated_pydantic_call(monkeypatch):
    """``.dict()`` on the request's IOC, twice per submission."""

    class Redis:
        def pipeline(self):
            return self

        def setex(self, *args):
            return self

        def incr(self, *args):
            return self

        def execute(self):
            return []

    class Enqueued:
        id = "celery-task-1"

    monkeypatch.setenv("GATEWAY_INTERNAL_SECRET", SECRET)
    monkeypatch.setattr(main, "redis_client", Redis())
    monkeypatch.setattr(
        main.run_threat_enrichment_task, "delay", lambda **kwargs: Enqueued()
    )
    main.limiter.reset()

    with warnings.catch_warnings():
        warnings.simplefilter("error", PydanticDeprecationWarning)
        response = TestClient(main.app).post(
            "/v1/analyze",
            json={"ioc": {"type": "domain", "value": "example.com"}},
            headers=HEADERS,
        )

    assert response.status_code == 202, response.text
