"""Registry token bucket.

At 1000 images the registry, not the worker pool, is the binding constraint: ten
images every fifteen minutes already implies a few hundred manifest fetches per
six-hour window, and registries throttle anonymous pulls well below that. So every
registry touch spends a token, digest resolution included.

The bucket lives in Postgres because that is where everything else already is, and
because at roughly one job per second the contention on a single counter row is
irrelevant.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def ensure_bucket(session: Session, registry: str, capacity: int, window_seconds: int) -> None:
    session.execute(
        text(
            """
            INSERT INTO registry_budget (registry, tokens, capacity, window_seconds,
                                         window_started_at)
            VALUES (:registry, :capacity, :capacity, :window_seconds, now())
            ON CONFLICT (registry) DO UPDATE
               SET capacity = EXCLUDED.capacity,
                   window_seconds = EXCLUDED.window_seconds
            """
        ),
        {"registry": registry, "capacity": capacity, "window_seconds": window_seconds},
    )


def try_consume(
    session: Session, registry: str, *, capacity: int, window_seconds: int, tokens: int = 1
) -> bool:
    """Spend ``tokens`` against the registry's budget.

    Returns False when the budget is exhausted; the caller should defer rather than
    fail, since backpressure is not an error.
    """
    ensure_bucket(session, registry, capacity, window_seconds)

    # Refill first. Two workers racing here both write the same full bucket, which is
    # harmless; the consume below is what has to be atomic, and a single UPDATE is.
    session.execute(
        text(
            """
            UPDATE registry_budget
               SET tokens = capacity, window_started_at = now()
             WHERE registry = :registry
               AND now() - window_started_at >= make_interval(secs => window_seconds)
            """
        ),
        {"registry": registry},
    )

    consumed = session.execute(
        text(
            """
            UPDATE registry_budget
               SET tokens = tokens - :tokens
             WHERE registry = :registry AND tokens >= :tokens
            RETURNING tokens
            """
        ),
        {"registry": registry, "tokens": tokens},
    ).scalar_one_or_none()

    return consumed is not None


def seconds_until_refill(session: Session, registry: str) -> int:
    """How long until this bucket refills, for choosing a defer delay."""
    remaining = session.execute(
        text(
            """
            SELECT GREATEST(
                0,
                EXTRACT(EPOCH FROM (
                    window_started_at + make_interval(secs => window_seconds) - now()
                ))
            )::int
              FROM registry_budget
             WHERE registry = :registry
            """
        ),
        {"registry": registry},
    ).scalar_one_or_none()
    return int(remaining or 0)
