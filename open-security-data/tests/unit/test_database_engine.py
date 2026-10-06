"""The engine is PostgreSQL's, and another database is refused by name (#778).

``app/utils/database.py`` had a branch for a SQLite ``DATABASE_URL``. It gave
the engine a ``StaticPool`` together with ``pool_size``, ``max_overflow`` and
``pool_timeout``, which ``StaticPool`` does not take, so with such a URL the
engine could not be created at all::

    TypeError: Invalid argument(s) 'pool_size','max_overflow','pool_timeout'
    sent to create_engine(), using configuration
    SQLiteDialect_pysqlite/StaticPool/Engine.

Nothing reached the branch: the stack and the documentation give the service
PostgreSQL, the tables use PostgreSQL types (``UUID``, ``INET``, ``CIDR``)
and the migrations are written for it, and the unit tests that want SQLite
build their own engine and compile those types themselves. The branch is
gone, and a URL that is not PostgreSQL's is refused for what it is.
"""

import pytest
from app.utils import database

SECRET = "pw-7f3a9c1e5b2d4f60"


@pytest.fixture
def engine_for(monkeypatch):
    """Build the service's engine for a URL; dispose of it afterwards."""
    made = []

    def build(url):
        monkeypatch.setattr(database, "_engine", None)
        monkeypatch.setattr(database, "_SessionLocal", None)
        monkeypatch.setattr(database.config.database, "url", url)
        engine = database.get_engine()
        made.append(engine)
        return engine

    yield build
    for engine in made:
        engine.dispose()


def test_the_branch_that_was_there_could_not_make_an_engine():
    """What the removed code asked of SQLAlchemy, asked again here."""
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    with pytest.raises(TypeError, match="pool_size"):
        create_engine(
            "sqlite://",
            pool_size=database.config.database.pool_size,
            max_overflow=database.config.database.max_overflow,
            pool_timeout=database.config.database.pool_timeout,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )


@pytest.mark.parametrize(
    "url, backend",
    [
        ("sqlite://", "sqlite"),
        ("sqlite:///data.db", "sqlite"),
        (f"sqlite+pysqlite:///{SECRET}.db", "sqlite"),
        (f"mysql+pymysql://data:{SECRET}@db.internal/data", "mysql"),
    ],
)
def test_a_database_that_is_not_postgresql_is_refused_by_name(engine_for, url, backend):
    with pytest.raises(RuntimeError) as refused:
        engine_for(url)

    message = str(refused.value)
    assert message.startswith(f"DATABASE_URL names a {backend} database")
    assert "needs PostgreSQL" in message
    # By the name of the backend: the URL holds a password.
    assert SECRET not in message
    assert url not in message
    # And no engine was kept for the next caller.
    assert database._engine is None


@pytest.mark.parametrize(
    "url",
    [
        f"postgresql://data:{SECRET}@db.internal:5432/data",
        f"postgresql+psycopg2://data:{SECRET}@db.internal/data",
    ],
)
def test_a_postgresql_url_gets_the_engine_with_the_pool_the_settings_ask_for(
    engine_for, monkeypatch, url
):
    # None of them SQLAlchemy's own default.
    monkeypatch.setattr(database.config.database, "pool_size", 7)
    monkeypatch.setattr(database.config.database, "max_overflow", 3)
    monkeypatch.setattr(database.config.database, "pool_timeout", 11)

    engine = engine_for(url)  # create_engine does not connect

    assert engine.dialect.name == "postgresql"
    assert engine.pool.size() == 7
    assert engine.pool._max_overflow == 3
    assert engine.pool._timeout == 11
    assert engine.pool._pre_ping is True
    # Statements without their parameters, in logs and in errors (#755).
    assert engine.hide_parameters is True
    assert database.get_db_session().get_bind() is engine


def test_an_unset_url_is_still_refused_before_anything_else(engine_for):
    with pytest.raises(RuntimeError, match="DATABASE_URL is not set"):
        engine_for("")
