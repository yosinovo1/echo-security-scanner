"""Engine and session factories.

The API is async (asyncpg); the worker and scheduler are plain synchronous
processes, because a worker runs exactly one scan at a time and therefore has no
concurrency to manage. Both share the models in ``app.domain.models``.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


@lru_cache
def sync_engine():
    settings = get_settings()
    return create_engine(settings.sync_dsn, pool_pre_ping=True, future=True)


@lru_cache
def sync_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=sync_engine(), expire_on_commit=False, future=True)


@contextmanager
def sync_session() -> Iterator[Session]:
    with sync_session_factory()() as session:
        yield session


@lru_cache
def async_engine():
    settings = get_settings()
    return create_async_engine(settings.async_dsn, pool_pre_ping=True)


@lru_cache
def async_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=async_engine(), expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with async_session_factory()() as session:
        yield session
