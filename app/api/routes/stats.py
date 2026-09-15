"""Operational statistics.

Beyond the brief. The argument for it is that no metrics system is being introduced:
``scan_run`` already holds one durable row per attempt, with its outcome, its error
and its wall-clock duration, because the brief's "handle scan failures gracefully"
required queryable history rather than log lines. That table *is* the time series,
so p95 scan time and the failure breakdown are SQL over data already on disk --
nothing sampled, nothing held in memory, nothing lost on restart.

A Prometheus ``/metrics`` endpoint would be a second reader of these same queries,
not a second source of truth. It is left out because nothing here scrapes.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    DurationStats,
    FailureReason,
    ImageStats,
    QueueStats,
    RunOutcomes,
    SeverityCounts,
    Stats,
)
from app.db.session import get_session
from app.domain.models import Image, JobStatus, RunStatus, ScanJob, ScanRun

router = APIRouter(prefix="/api", tags=["stats"])

#: Only the exception classes actually worth acting on differently fit in one screen,
#: and a long tail of one-offs is noise in a summary.
FAILURE_REASON_LIMIT = 10


@router.get(
    "/stats",
    response_model=Stats,
    summary="Operational statistics derived from scan history",
)
async def stats(
    response: Response,
    window_hours: int = Query(
        default=24,
        ge=1,
        le=720,
        description="How far back the run, duration and failure figures look.",
    ),
    session: AsyncSession = Depends(get_session),
):
    # Deliberately not behind the ETag validator the collection endpoints use. That
    # validator is keyed on the newest scan completion, which is correct for findings
    # -- they can only change when a scan completes -- but queue depth and backlog age
    # move continuously *between* scans. Serving a 304 here would hide exactly the
    # numbers that change fastest, so this endpoint is explicitly uncacheable.
    response.headers["Cache-Control"] = "no-store"

    cutoff = datetime.now(UTC) - timedelta(hours=window_hours)

    # Six round trips rather than one assembled query. They share no rows and no
    # join, and an operator-facing endpoint called by hand is the wrong place to
    # trade legibility for latency.
    job_counts = dict(
        (
            await session.execute(select(ScanJob.status, func.count()).group_by(ScanJob.status))
        ).all()
    )

    # Only jobs already due count as backlog: a deferred job is scheduled into the
    # future on purpose, and including it would report registry backpressure as a
    # worker shortage. statement_timestamp() rather than now() for the same reason
    # the queue uses it -- now() is frozen at transaction start.
    oldest_pending = await session.scalar(
        select(
            func.extract(
                "epoch", func.statement_timestamp() - func.min(ScanJob.scheduled_for)
            )
        ).where(
            ScanJob.status == JobStatus.PENDING,
            ScanJob.scheduled_for <= func.statement_timestamp(),
        )
    )

    image_row = (
        await session.execute(
            select(
                func.count(),
                func.count().filter(Image.enabled.is_(True)),
                func.count().filter(Image.last_scan_at.is_(None)),
                func.count().filter(Image.consecutive_failures > 0),
            ).select_from(Image)
        )
    ).one()

    run_counts = dict(
        (
            await session.execute(
                select(ScanRun.status, func.count())
                .where(ScanRun.completed_at >= cutoff)
                .group_by(ScanRun.status)
            )
        ).all()
    )

    # Successful runs only. A failed run's duration measures how long it took to give
    # up, and a skipped one never invoked Trivy at all; mixing either in makes the
    # percentiles say nothing about how long a scan takes.
    duration_row = (
        await session.execute(
            select(
                func.count(ScanRun.duration_ms),
                func.percentile_cont(0.5).within_group(ScanRun.duration_ms.asc()),
                func.percentile_cont(0.95).within_group(ScanRun.duration_ms.asc()),
                func.max(ScanRun.duration_ms),
            ).where(
                ScanRun.status == RunStatus.SUCCESS,
                ScanRun.completed_at >= cutoff,
                ScanRun.duration_ms.is_not(None),
            )
        )
    ).one()

    # persist writes `error` as "TypeName: message", so the class comes back out with
    # split_part and does not need storing a second time. A message with no colon --
    # the lease-expiry reap is the one that matters -- groups under itself, which is
    # the right answer: "worker died mid-scan" is its own failure mode.
    reason = func.split_part(ScanRun.error, ": ", 1)
    failures = (
        await session.execute(
            select(reason, func.count())
            .where(
                ScanRun.status == RunStatus.FAILED,
                ScanRun.completed_at >= cutoff,
                ScanRun.error.is_not(None),
            )
            .group_by(reason)
            .order_by(func.count().desc(), reason)
            .limit(FAILURE_REASON_LIMIT)
        )
    ).all()

    # The rollups from invariant 5, summed across current runs. Aggregating `finding`
    # instead would be ~2M rows at a thousand images to rederive numbers each scan
    # already committed alongside the findings they count.
    totals = (
        await session.execute(
            select(
                func.coalesce(func.sum(ScanRun.finding_count_critical), 0),
                func.coalesce(func.sum(ScanRun.finding_count_high), 0),
                func.coalesce(func.sum(ScanRun.finding_count_medium), 0),
                func.coalesce(func.sum(ScanRun.finding_count_low), 0),
                func.coalesce(func.sum(ScanRun.finding_count_unknown), 0),
            ).join(Image, Image.current_scan_run_id == ScanRun.id)
        )
    ).one()

    attempts = sum(run_counts.values())
    skipped = run_counts.get(RunStatus.SKIPPED, 0)

    return Stats(
        generated_at=datetime.now(UTC),
        window_hours=window_hours,
        queue=QueueStats(
            pending=job_counts.get(JobStatus.PENDING, 0),
            running=job_counts.get(JobStatus.RUNNING, 0),
            failed=job_counts.get(JobStatus.FAILED, 0),
            oldest_pending_age_seconds=(
                round(float(oldest_pending), 1) if oldest_pending is not None else None
            ),
        ),
        images=ImageStats(
            total=image_row[0],
            enabled=image_row[1],
            never_scanned=image_row[2],
            failing=image_row[3],
        ),
        runs=RunOutcomes(
            success=run_counts.get(RunStatus.SUCCESS, 0),
            failed=run_counts.get(RunStatus.FAILED, 0),
            skipped=skipped,
            skip_ratio=round(skipped / attempts, 3) if attempts else 0.0,
        ),
        scan_duration_ms=DurationStats(
            count=duration_row[0],
            p50=int(duration_row[1]) if duration_row[1] is not None else None,
            p95=int(duration_row[2]) if duration_row[2] is not None else None,
            max=duration_row[3],
        ),
        recent_failures=[FailureReason(reason=r, count=c) for r, c in failures],
        findings=SeverityCounts(
            CRITICAL=totals[0],
            HIGH=totals[1],
            MEDIUM=totals[2],
            LOW=totals[3],
            UNKNOWN=totals[4],
        ),
    )
