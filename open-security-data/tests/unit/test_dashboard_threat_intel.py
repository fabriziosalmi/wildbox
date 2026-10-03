"""GET /api/v1/dashboard/threat-intel is scoped to the caller's team (#570).

The endpoint counted every team's sources and indicators -- a cross-tenant
leak, since /api/v1/indicators/search already limits a team to its own rows
and the global ones (team_id IS NULL) -- and reported ``last_updated`` as
"one hour ago" when no collection run had completed. These tests run the
endpoint against an in-memory SQLite database holding two teams' data.
"""

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.api import main  # noqa: E402
from app.auth import GatewayUser  # noqa: E402
from app.models import CollectionRun, Indicator, Source  # noqa: E402


@compiles(UUID, "sqlite")
def _uuid_on_sqlite(_type, _compiler, **_kw):
    # The models use PostgreSQL's UUID type; SQLite stores it as hex text,
    # which is what SQLAlchemy binds a UUID to on a non-native dialect.
    return "CHAR(32)"


TEAM_A = uuid.uuid4()
TEAM_B = uuid.uuid4()
NOW = datetime.now(timezone.utc)


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [Source.__table__, Indicator.__table__, CollectionRun.__table__]
    Source.metadata.create_all(engine, tables=tables)
    db = sessionmaker(bind=engine)()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _client(db, team_id):
    user = GatewayUser(user_id=uuid.uuid4(), team_id=team_id, role="member")
    main.app.dependency_overrides[main.get_current_user] = lambda: user
    main.app.dependency_overrides[main.get_db] = lambda: db
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    main.app.dependency_overrides.clear()


def _source(db, name, team_id, enabled=True):
    source = Source(name=name, source_type="feed", team_id=team_id, enabled=enabled)
    db.add(source)
    db.flush()
    return source


def _indicators(db, source, count, created_at):
    for i in range(count):
        value = f"{source.name}-{created_at:%H%M}-{i}.example"
        db.add(
            Indicator(
                source_id=source.id,
                team_id=source.team_id,
                indicator_type="domain",
                value=value,
                normalized_value=value,
                created_at=created_at,
            )
        )


def _run(db, source, completed_at, status="completed"):
    db.add(
        CollectionRun(
            source_id=source.id,
            started_at=completed_at - timedelta(minutes=5),
            completed_at=completed_at,
            status=status,
        )
    )


@pytest.fixture
def two_teams(session):
    """Global, team A and team B rows, each team with distinct counts."""
    shared = _source(session, "global-feed", None)
    team_a = _source(session, "team-a-feed", TEAM_A)
    _source(session, "team-a-paused", TEAM_A, enabled=False)
    team_b = _source(session, "team-b-feed", TEAM_B)
    _source(session, "team-b-second", TEAM_B)
    _source(session, "team-b-third", TEAM_B)

    recent = NOW - timedelta(hours=1)
    earlier = NOW - timedelta(hours=30)
    _indicators(session, shared, 2, recent)
    _indicators(session, team_a, 3, recent)
    _indicators(session, team_a, 1, earlier)
    _indicators(session, team_b, 7, recent)
    _indicators(session, team_b, 5, earlier)

    _run(session, shared, NOW - timedelta(hours=6))
    _run(session, team_a, NOW - timedelta(hours=3))
    # Team B's run is the most recent of all: team A must not see its time.
    _run(session, team_b, NOW - timedelta(minutes=10))
    session.commit()
    return session


def _metrics(db, team_id):
    response = _client(db, team_id).get("/api/v1/dashboard/threat-intel")
    assert response.status_code == 200, response.text
    return response.json()


def test_a_team_counts_only_its_own_and_global_feeds(two_teams):
    metrics = _metrics(two_teams, TEAM_A)
    # global-feed, team-a-feed, team-a-paused
    assert metrics["total_feeds"] == 3
    assert metrics["active_feeds"] == 2


def test_a_team_counts_only_its_own_and_global_indicators(two_teams):
    metrics = _metrics(two_teams, TEAM_A)
    # Last 24 hours: 2 global + 3 team A; team B's 7 are not counted.
    assert metrics["new_indicators"] == 5
    # Previous 24 hours: team A's 1 (team B's 5 would make it 6): +400%.
    assert metrics["trends_change"] == 400.0


def test_the_other_team_sees_its_own_figures(two_teams):
    metrics = _metrics(two_teams, TEAM_B)
    assert metrics["total_feeds"] == 4
    assert metrics["active_feeds"] == 4
    assert metrics["new_indicators"] == 9
    assert metrics["trends_change"] == 80.0


def test_last_updated_is_the_last_run_the_team_can_see(two_teams):
    metrics = _metrics(two_teams, TEAM_A)
    last_updated = datetime.fromisoformat(metrics["last_updated"])
    if last_updated.tzinfo is None:  # SQLite drops the offset
        last_updated = last_updated.replace(tzinfo=timezone.utc)
    expected = NOW - timedelta(hours=3)
    assert abs(last_updated - expected) < timedelta(seconds=1)


def test_last_updated_is_null_without_a_completed_run(session):
    source = _source(session, "only-failed", TEAM_A)
    _run(session, source, NOW - timedelta(hours=2), status="failed")
    session.commit()

    metrics = _metrics(session, TEAM_A)
    assert metrics["last_updated"] is None


def test_last_updated_is_null_when_only_another_team_has_runs(session):
    other = _source(session, "team-b-only", TEAM_B)
    _run(session, other, NOW - timedelta(minutes=5))
    session.commit()

    assert _metrics(session, TEAM_A)["last_updated"] is None


# trends_change is null when the previous period is empty (#573): a change
# from zero has no percentage, and the endpoint reported +100% for it.


@pytest.mark.parametrize(
    "previous, current, expected",
    [
        (0, 0, None),
        (0, 7, None),
        (4, 0, -100.0),
        (4, 4, 0.0),
        (4, 5, 25.0),
        (5, 4, -20.0),
        (3, 4, 33.3),
    ],
)
def test_percent_change(previous, current, expected):
    assert main.percent_change(previous, current) == expected


def test_trends_change_is_null_without_indicators_in_the_previous_day(session):
    source = _source(session, "fresh-feed", TEAM_A)
    _indicators(session, source, 3, NOW - timedelta(hours=1))
    session.commit()

    metrics = _metrics(session, TEAM_A)
    assert metrics["new_indicators"] == 3
    assert metrics["trends_change"] is None


def test_trends_change_is_null_when_both_days_are_empty(session):
    _source(session, "quiet-feed", TEAM_A)
    session.commit()

    metrics = _metrics(session, TEAM_A)
    assert metrics["new_indicators"] == 0
    assert metrics["trends_change"] is None


def test_trends_change_is_minus_100_when_the_last_day_is_empty(session):
    source = _source(session, "stopped-feed", TEAM_A)
    _indicators(session, source, 2, NOW - timedelta(hours=30))
    session.commit()

    assert _metrics(session, TEAM_A)["trends_change"] == -100.0
