"""Test fixtures.

The queue is the one part of this system whose behaviour *is* PostgreSQL semantics
(``FOR UPDATE SKIP LOCKED``, partial unique indexes), so testing it against SQLite
would prove nothing. These fixtures reach for a real database and skip cleanly when
there is not one, which keeps `pytest` green on a machine with no Docker running.

They use a dedicated ``<database>_test`` database, created on demand. That is not
tidiness: ``queue.claim`` deliberately takes the globally next due job, so sharing a
database with a running stack means the tests claim the *system's* jobs and the
system claims theirs.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.domain.models import Base, Image


@pytest.fixture(scope="session")
def engine():
    settings = get_settings()
    test_db = f"{settings.postgres_db}_test"

    admin = create_engine(settings.sync_dsn, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            connection.execute(text("SELECT 1"))
            exists = connection.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": test_db}
            ).scalar()
            if not exists:
                connection.execute(text(f'CREATE DATABASE "{test_db}"'))
    except Exception as exc:
        pytest.skip(f"PostgreSQL not reachable at {settings.postgres_host}: {exc}")
    finally:
        admin.dispose()

    base, _, _ = settings.sync_dsn.rpartition("/")
    engine = create_engine(f"{base}/{test_db}", pool_pre_ping=True)
    # Rebuilt from the models every session rather than migrated into place:
    # create_all adds missing *tables* but never missing *columns*, so adding a column
    # would otherwise surface as UndefinedColumn across the whole suite for anyone who
    # had run the tests before. Nothing in this database is worth keeping between runs.
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session(engine):
    """A session whose writes are rolled back, so tests cannot see each other.

    ``join_transaction_mode="create_savepoint"`` lets production code call
    ``commit()`` normally while the outer transaction still discards everything.
    """
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


def _unique_image(session, prefix: str) -> Image:
    """An image no other test can collide with, even if a rollback is skipped."""
    record = Image(name=f"test-{prefix}-{uuid.uuid4().hex[:12]}", tag="test")
    session.add(record)
    session.flush()
    return record


@pytest.fixture
def image(session) -> Image:
    return _unique_image(session, "image")


@pytest.fixture
def other_image(session) -> Image:
    return _unique_image(session, "other")
