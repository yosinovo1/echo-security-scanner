"""Worker process: claim one job, scan, write, repeat.

Deliberately synchronous and single-job. One scan per process means a wedged Trivy
takes down one worker rather than every in-flight scan on the box, and it removes
concurrency control from this file entirely -- scale is replica count.
"""
from __future__ import annotations

import logging
import os
import signal
import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db.session import sync_session
from app.domain.models import Image, RunStatus, ScanJob, ScanRun
from app.jobs import queue
from app.registry.digest import (
    ImageNotFound,
    RateLimited,
    RegistryError,
    parse_reference,
    resolve_digest,
)
from app.scanner import persist, trivy
from app.scanner.parser import ParsedReport, TrivyReportError, parse_report

log = logging.getLogger("worker")

#: Fallback wait when a registry throttles us without saying for how long. Registries
#: normally send ``Retry-After``; this only covers the ones that do not.
DEFAULT_DEFER_SECONDS = 300


class _Shutdown:
    def __init__(self) -> None:
        self.requested = False
        signal.signal(signal.SIGTERM, self._handle)
        signal.signal(signal.SIGINT, self._handle)

    def _handle(self, *_args: object) -> None:
        log.info("shutdown requested; finishing current job")
        self.requested = True


def _now() -> datetime:
    return datetime.now(UTC)


def _last_successful_run(session: Session, image_id: int) -> ScanRun | None:
    return (
        session.execute(
            select(ScanRun)
            .where(ScanRun.image_id == image_id, ScanRun.status == RunStatus.SUCCESS)
            .order_by(ScanRun.completed_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )


def _is_unchanged(
    previous: ScanRun | None, digest: str, trivy_version: str, db_version: str, flags_hash: str
) -> bool:
    """The skip invariant.

    Identical image bytes, scanner, vulnerability database and flags cannot produce
    different findings. This is a proof, not the "scanned recently" heuristic it
    replaces -- which would both skip scans that a fresh database would light up and
    run scans that could not possibly differ.
    """
    return (
        previous is not None
        and previous.digest == digest
        and previous.trivy_version == trivy_version
        and previous.trivy_db_version == db_version
        and previous.scan_flags_hash == flags_hash
    )


def _execute(session: Session, job: ScanJob, settings: Settings) -> None:
    image = session.get(Image, job.image_id)
    if image is None:  # pragma: no cover - FK makes this unreachable in practice
        queue.complete(session, job)
        session.commit()
        return

    # Probed per job, not once at startup: a worker outlives the vulnerability DB
    # refresh, and a stale db_version would make the skip invariant claim nothing
    # had changed when the database underneath had. The probe is a local file read.
    trivy_version, db_version = trivy.probe_versions(settings)
    flags_hash = trivy.scan_flags_hash(settings)
    reference = parse_reference(image.name, image.tag)
    started_at = _now()

    def meta(digest: str | None) -> persist.RunMetadata:
        return persist.RunMetadata(
            digest=digest,
            trivy_version=trivy_version,
            trivy_db_version=db_version,
            scan_flags_hash=flags_hash,
            started_at=started_at,
            completed_at=_now(),
        )

    # Everything the decision needs is read up front, then the transaction ends: a
    # scan takes minutes, and holding a connection (and its snapshot) open across a
    # subprocess pins one of a small pool and blocks vacuum for the duration.
    previous = _last_successful_run(session, image.id)
    session.commit()

    digest = resolve_digest(reference)

    if _is_unchanged(previous, digest, trivy_version, db_version, flags_hash):
        # Applies to time-sensitive jobs too: urgency justifies reordering work, not
        # doing work whose result is already known.
        persist.record_skip(session, image, job, meta(digest), reason="unchanged")
        queue.complete(session, job)
        session.commit()
        log.info("skipped %s: digest and vulnerability DB unchanged", image.reference)
        return

    raw = trivy.run_scan(image.reference, settings)
    report: ParsedReport = parse_report(raw)

    # Trust what Trivy actually scanned over what we resolved a moment earlier: the
    # tag can move in between.
    run_meta = meta(report.digest or digest)
    persist.record_success(session, image, job, report, run_meta)
    queue.complete(session, job)
    session.commit()
    log.info(
        "scanned %s: %d findings in %sms",
        image.reference,
        len(report.findings),
        run_meta.duration_ms,
    )


def _defer_for_backpressure(
    session: Session, job: ScanJob, error: RateLimited | trivy.TrivyRateLimited
) -> None:
    """Registry throttling is backpressure, not failure.

    No ``scan_run`` row is written, because nothing was attempted -- and crucially no
    attempt is burnt, or a throttled registry would walk every image to permanently
    failed. ``Retry-After`` is the registry's own answer to "how long"; it is better
    information than any local model of its limits, which is the whole reason this
    replaced a token bucket.
    """
    session.rollback()
    delay = getattr(error, "retry_after", None) or DEFAULT_DEFER_SECONDS
    queue.defer(session, job, delay, f"{type(error).__name__}: {error}")
    session.commit()
    log.info("deferred job %s for %ss: registry throttled us", job.id, delay)


def _record_failure(
    session: Session, job: ScanJob, error: Exception, settings: Settings, permanent: bool
) -> None:
    session.rollback()
    image = session.get(Image, job.image_id)
    message = f"{type(error).__name__}: {error}"

    if image is not None:
        persist.record_failure(
            session,
            image,
            job,
            persist.RunMetadata(
                digest=None,
                trivy_version=None,
                trivy_db_version=None,
                scan_flags_hash=None,
                started_at=_now(),
                completed_at=_now(),
            ),
            error=message,
        )

    queue.fail(
        session,
        job,
        message,
        # A reference that does not exist will not start existing on retry, so burn
        # the allowance immediately rather than backing off five times.
        max_attempts=1 if permanent else settings.max_attempts,
        backoff_base_seconds=settings.backoff_base_seconds,
        backoff_max_seconds=settings.backoff_max_seconds,
    )
    session.commit()
    log.warning("job %s failed (permanent=%s): %s", job.id, permanent, message)


def run_once(session: Session, settings: Settings) -> bool:
    """Process at most one job. Returns True if a job was claimed."""
    queue.reap_expired_leases(session)
    job = queue.claim(session, lease_seconds=settings.lease_seconds)
    session.commit()

    if job is None:
        return False

    try:
        _execute(session, job, settings)
    except ImageNotFound as exc:
        _record_failure(session, job, exc, settings, permanent=True)
    # Before the broader clause below: both subclass an exception listed there.
    except (RateLimited, trivy.TrivyRateLimited) as exc:
        _defer_for_backpressure(session, job, exc)
    except (RegistryError, trivy.TrivyError, TrivyReportError) as exc:
        _record_failure(session, job, exc, settings, permanent=False)
    except Exception as exc:
        log.exception("unexpected error on job %s", job.id)
        _record_failure(session, job, exc, settings, permanent=False)
    return True


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = get_settings()
    shutdown = _Shutdown()

    # Probed here only to fail fast and log what we are running against; the
    # authoritative probe happens per job.
    log.info("worker up; trivy %s, vulnerability db %s", *trivy.probe_versions(settings))

    with sync_session() as session:
        while not shutdown.requested:
            try:
                did_work = run_once(session, settings)
            except Exception:
                log.exception("worker loop error")
                session.rollback()
                did_work = False
            if not did_work:
                time.sleep(settings.worker_poll_seconds)

    log.info("worker stopped")


if __name__ == "__main__":
    main()
