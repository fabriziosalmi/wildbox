"""identity must not publish its API documentation in production (#496).

/docs, /redoc and /openapi.json map every route, admin and internal ones
included. Like agents, responder and cspm, identity serves them only when
ENVIRONMENT is not production.
"""

import importlib
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _app(monkeypatch, environment):
    monkeypatch.setenv("ENVIRONMENT", environment)
    import app.main as main

    return importlib.reload(main).app


@pytest.mark.parametrize("environment", ["production"])
def test_docs_are_not_served_in_production(monkeypatch, environment):
    app = _app(monkeypatch, environment)
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None


@pytest.mark.parametrize("environment", ["development"])
def test_docs_are_served_in_development(monkeypatch, environment):
    app = _app(monkeypatch, environment)
    assert app.docs_url == "/docs"
    assert app.redoc_url == "/redoc"
    assert app.openapi_url == "/openapi.json"
