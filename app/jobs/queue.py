"""The queue, which is just Postgres.

``SELECT ... FOR UPDATE SKIP LOCKED`` lets N workers claim disjoint rows without a
broker. The decisive property is that a job's completion and the findings it
produced commit in the *same transaction*: there is no second system to reconcile
with, so no at-least-once delivery to defend against with idempotency keys.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.domain.models import JobStatus, ScanJob

#: Key for the scheduler's advisory lock. Arbitrary, but must be stable.
SCHEDULER_LOCK_KEY = 0x5CA45CA4

#: Priority given to a job the caller marked time-sensitive.
PRIORITY_TIME_SENSITIVE = 100
PRIORITY_SCHEDULED = 0

#: Recorded on a job whose worker stopped renewing its lease. Shared with the
#: scheduler, which writes it onto the scan_run it opens for the dead attempt.
LEASE_EXPIRED_ERROR = "lease expired; worker presumed dead"


@dataclass(frozen=True, slots=True)
class ReapedJob:
    """A job returned to the queue because its worker stopped reporting."""

    job_id: int
    image_id: int
    #: True if this reap used the job's last attempt, so the job gave up.
    exhausted: bool


def _now() -> datetime:
    return datetime.now(UTC)


def build_enqueue_statement(
    image_id: int,
    *,
    priority: int = PRIORITY_SCHEDULED,
    scheduled_for: datetime | None = None,
):
    """Insert a job unless the image already has one pending or running.

    Exclusion is enforced by the ``uq_scan_job_active`` partial unique index rather
    than by a read-then-write, so concurrent callers cannot both win.

    Returned as a statement rather than executed so the synchronous scheduler and the
    async API can share one definition instead of keeping two in step.
    """
    return (
        insert(ScanJob)
        .values(
            image_id=image_id,
            status=JobStatus.PENDING.value,
            priority=priority,
            scheduled_for=scheduled_for or _now(),
        )
        .on_conflict_do_nothing(
            index_elements=[ScanJob.image_id],
            index_where=text("status IN ('pending', 'running')"),
        )
        .returning(ScanJob.id)
    )


def build_promote_statement(image_id: int):
    """Raise an already-pending job to the time-sensitive lane.

    Lets an urgent request overtake without violating the one-active-job invariant.
    """
    return (
        update(ScanJob)
        .where(
            ScanJob.image_id == image_id,
            ScanJob.status == JobStatus.PENDING,
            ScanJob.priority < PRIORITY_TIME_SENSITIVE,
        )
        .values(priority=PRIORITY_TIME_SENSITIVE, scheduled_for=_now())
        .returning(ScanJob.id)
    )


def enqueue(
    session: Session,
    image_id: int,
    *,
    priority: int = PRIORITY_SCHEDULED,
    scheduled_for: datetime | None = None,
) -> bool:
    """Add a job. Returns True if a row was inserted."""
    statement = build_enqueue_statement(
        image_id, priority=priority, scheduled_for=scheduled_for
    )
    return session.execute(statement).scalar_one_or_none() is not None


def promote(session: Session, image_id: int) -> bool:
    """Promote a pending job. Returns True if one was promoted."""
    return (
        session.execute(build_promote_statement(image_id)).scalar_one_or_none() is not None
    )


def claim(session: Session, *, lease_seconds: int) -> ScanJob | None:
    """Claim the next due job, or return None.

    Ordering is priority first, then scheduled time, so a time-sensitive job
    overtakes the scheduled baseline.
    """
    job = (
        session.execute(
            select(ScanJob)
            .where(
                ScanJob.status == JobStatus.PENDING,
                # statement_timestamp(), not now(): now() is frozen at transaction
                # start, so a job enqueued after this transaction began would look
                # not-yet-due. A queue wants "due as of this moment".
                ScanJob.scheduled_for <= func.statement_timestamp(),
            )
            .order_by(ScanJob.priority.desc(), ScanJob.scheduled_for)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        .scalars()
        .first()
    )
    if job is None:
        return None

    job.status = JobStatus.RUNNING
    job.lease_until = _now() + timedelta(seconds=lease_seconds)
    session.flush()
    return job


def complete(session: Session, job: ScanJob) -> None:
    job.status = JobStatus.DONE
    job.lease_until = None
    job.last_error = None


def fail(
    session: Session,
    job: ScanJob,
    error: str,
    *,
    max_attempts: int,
    backoff_base_seconds: int,
    backoff_max_seconds: int,
) -> None:
    """Record a failure, retrying with exponential backoff until attempts run out.

    A permanently failed job releases the partial unique index, so the scheduler is
    free to enqueue the image again at its next natural due time -- failure slows an
    image down, it never wedges the queue.
    """
    job.attempts += 1
    job.last_error = error[:4000]
    job.lease_until = None

    if job.attempts >= max_attempts:
        job.status = JobStatus.FAILED
        return

    delay = min(backoff_base_seconds * (2 ** (job.attempts - 1)), backoff_max_seconds)
    job.status = JobStatus.PENDING
    job.scheduled_for = _now() + timedelta(seconds=delay)


def defer(session: Session, job: ScanJob, delay_seconds: int, reason: str) -> None:
    """Put a job back without counting an attempt.

    Used when a registry throttles us: that is backpressure, not a failure, and must
    not burn the retry allowance -- otherwise a throttled registry would walk every
    image to permanently failed.
    """
    job.status = JobStatus.PENDING
    job.lease_until = None
    job.last_error = reason[:4000]
    job.scheduled_for = _now() + timedelta(seconds=delay_seconds)


def reap_expired_leases(session: Session, *, max_attempts: int) -> list[ReapedJob]:
    """Return jobs whose worker died back to the queue.

    The lease, not the worker, owns liveness: a killed process leaves a row whose
    ``lease_until`` simply passes.

    A reaped attempt counts against ``max_attempts`` exactly like one a worker lived
    long enough to report, because the alternative is a job that can never give up.
    A scan that *kills* its worker -- an OOM on a large image, a Trivy crash, a node
    eviction -- never reaches ``fail``, so without this it would be re-claimed
    forever, taking down one more worker each time, while ``image
    .consecutive_failures`` stayed at zero because no job ever exhausted and the
    per-image backoff therefore never engaged.

    The caller is handed what was reaped so the dead attempt can be recorded as a
    ``scan_run`` like any other failure; see ``scheduler.tick``.
    """
    statement = (
        update(ScanJob)
        .where(
            ScanJob.status == JobStatus.RUNNING,
            ScanJob.lease_until < func.statement_timestamp(),
        )
        .values(
            status=case(
                (ScanJob.attempts + 1 >= max_attempts, JobStatus.FAILED.value),
                else_=JobStatus.PENDING.value,
            ),
            lease_until=None,
            attempts=ScanJob.attempts + 1,
            last_error=LEASE_EXPIRED_ERROR,
        )
        .returning(ScanJob.id, ScanJob.image_id, ScanJob.status)
    )
    return [
        ReapedJob(job_id=job_id, image_id=image_id, exhausted=status == JobStatus.FAILED)
        for job_id, image_id, status in session.execute(statement)
    ]


def try_scheduler_lock(session: Session) -> bool:
    """Session-scoped advisory lock so extra scheduler replicas idle harmlessly."""
    return bool(
        session.execute(
            select(func.pg_try_advisory_lock(SCHEDULER_LOCK_KEY))
        ).scalar_one()
    )


def release_scheduler_lock(session: Session) -> None:
    session.execute(select(func.pg_advisory_unlock(SCHEDULER_LOCK_KEY)))
