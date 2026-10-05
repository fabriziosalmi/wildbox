"""Fixtures shared by guardian's unit tests."""

import pytest

from tests.unit import identity_stub


@pytest.fixture
def identity_contacts(settings, monkeypatch):
    """identity, stood in: guardian asks it who may be e-mailed (#705).

    Without this fixture guardian has no contacts secret, as a deployment
    that has not set one: it asks nothing, and only the addresses a team
    typed into a rule or a schedule can be written to.
    """
    from apps.core import notifications

    stub = identity_stub.Identity()
    settings.TEAM_CONTACTS_URL = identity_stub.URL
    settings.TEAM_CONTACTS_SECRET = identity_stub.SECRET
    monkeypatch.setattr(notifications, "_session", lambda: stub)
    return stub
