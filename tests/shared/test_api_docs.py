"""
Tests for the rule that decides when a service publishes its API schema.

Every FastAPI service builds its application with ``api_docs_urls``, so this
is the one place where "development only" is decided (#679). Each service
also has a ``test_api_docs_exposure.py`` that asks its real application for
the three paths; these tests pin the rule itself, including the values a
deployment can get wrong.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from open_security_shared.api_docs import api_docs_enabled, api_docs_urls

PATHS = ("/docs", "/redoc", "/openapi.json")

ENABLED = {
    "docs_url": "/docs",
    "redoc_url": "/redoc",
    "openapi_url": "/openapi.json",
}
DISABLED = {"docs_url": None, "redoc_url": None, "openapi_url": None}

DEVELOPMENT = ["development", "Development", "DEVELOPMENT", " development\n"]
NOT_DEVELOPMENT = [
    "production",
    "Production",
    "staging",
    "test",
    "dev",
    "development-eu",
    "not development",
    "",
    "   ",
    None,
    True,
    1,
]


@pytest.mark.parametrize("environment", DEVELOPMENT)
def test_development_enables_schema_and_pages(environment):
    assert api_docs_enabled(environment) is True
    assert api_docs_urls(environment) == ENABLED


@pytest.mark.parametrize("environment", NOT_DEVELOPMENT)
def test_anything_else_disables_them(environment):
    assert api_docs_enabled(environment) is False
    assert api_docs_urls(environment) == DISABLED


@pytest.mark.parametrize(
    "environment, status",
    [("development", 200), ("production", 404), ("staging", 404), (None, 404)],
)
def test_an_application_built_with_the_urls(environment, status):
    client = TestClient(FastAPI(**api_docs_urls(environment)))

    assert {path: client.get(path).status_code for path in PATHS} == dict.fromkeys(
        PATHS, status
    )


def test_each_call_returns_its_own_mapping():
    # A caller that edits what it got must not change the rule for the next.
    api_docs_urls("development")["openapi_url"] = None
    api_docs_urls("production")["docs_url"] = "/docs"

    assert api_docs_urls("development") == ENABLED
    assert api_docs_urls("production") == DISABLED
