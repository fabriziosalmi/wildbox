"""
Database utilities and session management
"""

from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from app.config import get_config

config = get_config()

# Lazy engine/session: built on first use so this module imports cleanly even
# when DATABASE_URL is unset (CLI, tests, partial env) instead of crashing at
# import time on create_engine("").
_engine = None
_SessionLocal = None


def _init_engine():
    global _engine, _SessionLocal
    if _engine is None:
        url = config.database.url
        if not url:
            raise RuntimeError(
                "DATABASE_URL is not set — configure it before accessing the database."
            )
        is_sqlite = "sqlite" in url
        _engine = create_engine(
            url,
            pool_size=config.database.pool_size,
            max_overflow=config.database.max_overflow,
            pool_timeout=config.database.pool_timeout,
            pool_pre_ping=True,
            echo=config.database.echo,
            poolclass=StaticPool if is_sqlite else None,
            connect_args={"check_same_thread": False} if is_sqlite else {},
        )
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _engine


def get_engine():
    """Return the lazily-created SQLAlchemy engine."""
    return _init_engine()


def get_db_session() -> Session:
    """Get a database session"""
    _init_engine()
    return _SessionLocal()


@contextmanager
def get_db():
    """Context manager for database sessions"""
    _init_engine()
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """
    Create all database tables.

    NOTE: this is for a *fresh* database only. create_all() emits CREATE TABLE
    and never ALTER TABLE, so it cannot bring an existing database forward: any
    column added after the database was first created stays missing forever,
    which is what happened to the team_id tenancy columns (WILDBO-DOM-01).

    Schema changes go through alembic (see open-security-data/alembic/). The
    deployment path is:

        alembic upgrade head

    and for a database that predates the alembic scaffolding:

        alembic stamp 0001_baseline && alembic upgrade head
    """
    from app.models import Base
    Base.metadata.create_all(bind=get_engine())


def run_migrations() -> None:
    """
    Bring the database up to head. Safe to call at startup.

    Prefer this over create_tables(): it creates a fresh schema *and* migrates an
    existing one, so the two paths cannot diverge.
    """
    import os
    from alembic import command
    from alembic.config import Config

    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cfg = Config(os.path.join(here, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(here, "alembic"))
    command.upgrade(cfg, "head")


def drop_tables():
    """Drop all database tables"""
    from app.models import Base
    Base.metadata.drop_all(bind=get_engine())
