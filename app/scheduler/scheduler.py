"""Scheduler process: decide which images are due and enqueue them.

Safe to run more than one replica. Extra replicas fail to take the advisory lock and
idle, so the deployment gets failover without a leader election.
"""
from __future__ import annotations

import logging
import os
import signal
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db.session import sync_session
from app.domain.models import Image, JobStatus, ScanJob
from app.jobs import queue

log = logging.getLogger("scheduler")


class _Shutdown:
    def __init__(self) -> None:
        self.requested = False
        signal.signal(signal.SIGTERM, self._handle)
        signal.signal(signal.SIGINT, self._handle)

    def _handle(self, *_args: object) -> None:
        self.requested = True


def _now() -> datetime:
    return datetime.now(UTC)


def next_due_at(image: Image, default_interval: int) -> datetime:
    """When this image should next be scanned.

    A never-scanned image is due immediately. There is deliberately no cold-start
    jitter: enqueueing is not scanning. A burst of due images becomes a burst of
    queue rows, and concurrency is still bounded by worker replica count and the
    registry itself, so spreading the enqueue only delays the first results. The
    steady-state spread comes free from the rate at which the queue drains.
    """
    interval = image.scan_interval_seconds or default_interval
    if image.last_scan_at is None:
        return image.created_at
    return image.last_scan_at + timedelta(seconds=interval)


def due_images(session: Session, settings: Settings) -> list[Image]:
    """Enabled images with no active job whose next due time has passed."""
    active = select(ScanJob.image_id).where(
        ScanJob.status.in_([JobStatus.PENDING, JobStatus.RUNNING])
    )
    candidates = (
        session.execute(select(Image).where(Image.enabled.is_(True), Image.id.not_in(active)))
        .scalars()
        .all()
    )
    now = _now()
    interval = settings.default_scan_interval_seconds
    return [i for i in candidates if next_due_at(i, interval) <= now]


def tick(session: Session, settings: Settings) -> int:
    """One scheduling pass. Returns the number of jobs enqueued."""
    queue.reap_expired_leases(session)

    enqueued = 0
    for image in due_images(session, settings):
        # The partial unique index is the real guard; a False here just means another
        # replica got there first.
        if queue.enqueue(session, image.id):
            enqueued += 1
            log.info("enqueued %s", image.reference)
    session.commit()
    return enqueued


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = get_settings()
    shutdown = _Shutdown()

    with sync_session() as session:
        holds_lock = False
        while not shutdown.requested:
            try:
                if not holds_lock:
                    holds_lock = queue.try_scheduler_lock(session)
                    if not holds_lock:
                        log.debug("another scheduler holds the lock; standing by")
                    else:
                        log.info("scheduler lock acquired")
                if holds_lock:
                    tick(session, settings)
            except Exception:
                log.exception("scheduler tick failed")
                session.rollback()
                holds_lock = False
            time.sleep(settings.scheduler_tick_seconds)

        if holds_lock:
            queue.release_scheduler_lock(session)
    log.info("scheduler stopped")


if __name__ == "__main__":
    main()
