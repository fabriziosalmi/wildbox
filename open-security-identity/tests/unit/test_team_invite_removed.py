"""identity has no team-invite endpoint (#570).

POST /api/v1/admin/teams/{team_id}/invite answered "Invitation sent
successfully" to a team owner or admin and did nothing: no invitation was
stored or sent, and the body was not even read. It is removed rather than
left to report something that did not happen.
"""

import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.main import app  # noqa: E402

INVITE_PATH = "/api/v1/admin/teams/{team_id}/invite"


def test_the_openapi_schema_does_not_document_an_invite():
    # app.routes holds the included routers lazily in this FastAPI release,
    # so the schema is the complete list of what identity serves.
    paths = app.openapi()["paths"]
    assert INVITE_PATH not in paths
    assert not any(path.endswith("/invite") for path in paths)


@pytest.mark.parametrize("method", ["post", "get", "put"])
def test_a_request_to_the_old_path_is_not_found(method):
    # No credentials: the removed endpoint answered 401 before it answered
    # anything else, so a 404/405 here means no route matched at all.
    client = TestClient(app)
    response = getattr(client, method)(
        INVITE_PATH.format(team_id=uuid.uuid4()),
        **({"json": {"email": "invitee@example.com"}} if method != "get" else {}),
    )
    assert response.status_code in (404, 405), response.text
