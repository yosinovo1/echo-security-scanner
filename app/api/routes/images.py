"""Image endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.api.deps import PageParams, apply_freshness, page_params, severity_filter
from app.api.schemas import (
    CveInImage,
    ImageSummary,
    PackageRef,
    Page,
    Pagination,
    ScanRequestAccepted,
    SeverityCounts,
)
from app.config import Settings, get_settings
from app.db.session import get_session
from app.domain.models import Cve, Finding, Image, Package, ScanRun
from app.domain.severity import Severity, rank
from app.jobs import queue

router = APIRouter(prefix="/api", tags=["images"])


@router.get(
    "/images",
    response_model=Page[ImageSummary],
    summary="List scanned images with per-severity CVE counts",
)
async def list_images(
    response: Response,
    params: PageParams = Depends(page_params),
    not_modified: bool = Depends(apply_freshness),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    if not_modified:
        return Response(status_code=304, headers=dict(response.headers))

    total = await session.scalar(select(func.count()).select_from(Image)) or 0
    images = (
        (
            await session.execute(
                select(Image)
                .order_by(Image.name, Image.tag)
                .limit(params.limit)
                .offset(params.offset)
            )
        )
        .scalars()
        .all()
    )

    summaries = {
        image.id: ImageSummary(
            name=image.name,
            tag=image.tag,
            last_scan_at=image.last_scan_at,
            last_scan_status=image.last_scan_status,
            consecutive_failures=image.consecutive_failures,
            scan_interval_seconds=image.scan_interval_seconds
            or settings.default_scan_interval_seconds,
            severity_counts=SeverityCounts(),
        )
        for image in images
    }

    if summaries:
        # Digest and severity counts both come off each image's current run, which is
        # by definition its last *successful* one -- a skip never repoints it. The
        # counts are read rather than aggregated: recomputing them would mean summing
        # the finding table for every image on every request, which is ~200k rows per
        # page at a thousand images, to rederive a number the scan already knew.
        runs = await session.execute(
            select(
                ScanRun.image_id,
                ScanRun.digest,
                ScanRun.finding_count_critical,
                ScanRun.finding_count_high,
                ScanRun.finding_count_medium,
                ScanRun.finding_count_low,
                ScanRun.finding_count_unknown,
            )
            .join(Image, Image.current_scan_run_id == ScanRun.id)
            .where(ScanRun.image_id.in_(list(summaries)))
        )
        for image_id, digest, *counts in runs:
            summary = summaries[image_id]
            summary.digest = digest
            summary.severity_counts = SeverityCounts(
                CRITICAL=counts[0] or 0,
                HIGH=counts[1] or 0,
                MEDIUM=counts[2] or 0,
                LOW=counts[3] or 0,
                UNKNOWN=counts[4] or 0,
            )
            summary.total_cves = summary.severity_counts.total

    return Page[ImageSummary](
        items=list(summaries.values()),
        pagination=Pagination(total=total, limit=params.limit, offset=params.offset),
    )


@router.post(
    "/images/{image_name:path}/{tag}/scan",
    response_model=ScanRequestAccepted,
    status_code=202,
    summary="Request a scan of one image now",
)
async def request_scan(
    image_name: str,
    tag: str,
    time_sensitive: bool = Query(
        default=False,
        description=(
            "Jump the queue. Reorders work only: the scan still yields to a "
            "registry that is throttling us, and is still skipped if the image and "
            "vulnerability database are provably unchanged."
        ),
    ),
    session: AsyncSession = Depends(get_session),
):
    """Enqueue an out-of-band scan.

    Beyond the brief, but it is what makes the time-sensitive lane reachable: without
    a trigger, priority would be a column nothing ever sets.
    """
    image = (
        await session.execute(select(Image).where(Image.name == image_name, Image.tag == tag))
    ).scalar_one_or_none()
    if image is None:
        raise HTTPException(status_code=404, detail=f"unknown image {image_name}:{tag}")

    priority = queue.PRIORITY_TIME_SENSITIVE if time_sensitive else queue.PRIORITY_SCHEDULED
    enqueued = (
        await session.execute(queue.build_enqueue_statement(image.id, priority=priority))
    ).scalar_one_or_none()

    if enqueued is not None:
        await session.commit()
        return ScanRequestAccepted(
            status="queued", job_id=enqueued, time_sensitive=time_sensitive
        )

    # A job was already active. Urgency still applies: promote it rather than
    # queueing a duplicate.
    if time_sensitive:
        promoted = (
            await session.execute(queue.build_promote_statement(image.id))
        ).scalar_one_or_none()
        if promoted is not None:
            await session.commit()
            return ScanRequestAccepted(status="promoted", job_id=promoted, time_sensitive=True)

    return ScanRequestAccepted(
        status="already_queued", job_id=None, time_sensitive=time_sensitive
    )


@router.get(
    "/images/{image_name:path}/{tag}/cves",
    response_model=Page[CveInImage],
    summary="List the CVEs found in one image",
)
async def image_cves(
    image_name: str,
    tag: str,
    response: Response,
    params: PageParams = Depends(page_params),
    severity: Severity | None = Depends(severity_filter),
    not_modified: bool = Depends(apply_freshness),
    session: AsyncSession = Depends(get_session),
):
    if not_modified:
        return Response(status_code=304, headers=dict(response.headers))

    image = (
        await session.execute(select(Image).where(Image.name == image_name, Image.tag == tag))
    ).scalar_one_or_none()
    if image is None:
        raise HTTPException(status_code=404, detail=f"unknown image {image_name}:{tag}")
    if image.current_scan_run_id is None:
        return Page[CveInImage](
            items=[],
            pagination=Pagination(total=0, limit=params.limit, offset=params.offset),
        )

    first_run = aliased(ScanRun)
    last_run = aliased(ScanRun)

    conditions = [
        Finding.image_id == image.id,
        Finding.last_seen_run_id == image.current_scan_run_id,
    ]
    if severity is not None:
        conditions.append(Finding.severity_rank == rank(severity))

    total = (
        await session.scalar(select(func.count()).select_from(Finding).where(*conditions))
    ) or 0

    rows = await session.execute(
        select(
            Finding.cve_id,
            Cve.title,
            Finding.severity,
            Package.name,
            Package.version,
            Package.type,
            Finding.fixed_version,
            first_run.completed_at,
            last_run.completed_at,
        )
        .join(Cve, Cve.id == Finding.cve_id)
        .join(Package, Package.id == Finding.package_id)
        .join(first_run, first_run.id == Finding.first_seen_run_id)
        .join(last_run, last_run.id == Finding.last_seen_run_id)
        .where(*conditions)
        .order_by(Finding.severity_rank.desc(), Finding.cve_id)
        .limit(params.limit)
        .offset(params.offset)
    )

    items = [
        CveInImage(
            cve_id=cve_id,
            title=title,
            severity=Severity(severity_value),
            package=PackageRef(name=pkg_name, version=pkg_version, type=pkg_type),
            fixed_version=fixed_version,
            first_seen_at=first_seen,
            last_seen_at=last_seen,
        )
        for (
            cve_id,
            title,
            severity_value,
            pkg_name,
            pkg_version,
            pkg_type,
            fixed_version,
            first_seen,
            last_seen,
        ) in rows
    ]

    return Page[CveInImage](
        items=items,
        pagination=Pagination(total=total, limit=params.limit, offset=params.offset),
    )
