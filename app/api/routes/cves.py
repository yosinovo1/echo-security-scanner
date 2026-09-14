"""CVE endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import PageParams, apply_freshness, page_params, severity_filter
from app.api.schemas import CveSummary, ImageAffectedByCve, PackageRef, Page, Pagination
from app.db.session import get_session
from app.domain.models import Cve, Finding, Image, Package, ScanRun
from app.domain.severity import Severity, rank

router = APIRouter(prefix="/api", tags=["cves"])


@router.get(
    "/cves",
    response_model=Page[CveSummary],
    summary="List every unique CVE found across all scanned images",
)
async def list_cves(
    response: Response,
    params: PageParams = Depends(page_params),
    severity: Severity | None = Depends(severity_filter),
    not_modified: bool = Depends(apply_freshness),
    session: AsyncSession = Depends(get_session),
):
    if not_modified:
        return Response(status_code=304, headers=dict(response.headers))

    # "Currently found in at least one image". Maintained by the same recompute as
    # max_severity, so this is an indexed column rather than an EXISTS over the whole
    # finding table -- which at a thousand images meant hashing two million rows to
    # answer a question the last scan already settled.
    conditions = [Cve.affected_image_count > 0]
    if severity is not None:
        # Filters on the rollup, not on any single image's vendor rating.
        conditions.append(Cve.max_severity_rank == rank(severity))

    total = await session.scalar(select(func.count()).select_from(Cve).where(*conditions)) or 0

    rows = await session.execute(
        select(
            Cve.id,
            Cve.title,
            Cve.max_severity,
            Cve.published_at,
            Cve.last_modified_at,
            Cve.affected_image_count,
        )
        .where(*conditions)
        .order_by(Cve.max_severity_rank.desc(), Cve.id)
        .limit(params.limit)
        .offset(params.offset)
    )

    items = [
        CveSummary(
            cve_id=cve_id,
            title=title,
            max_severity=Severity(max_severity),
            published_at=published_at,
            last_modified_at=last_modified_at,
            affected_image_count=count or 0,
        )
        for cve_id, title, max_severity, published_at, last_modified_at, count in rows
    ]

    return Page[CveSummary](
        items=items,
        pagination=Pagination(total=total, limit=params.limit, offset=params.offset),
    )


@router.get(
    "/cves/{cve_id}/images",
    response_model=Page[ImageAffectedByCve],
    summary="List every image affected by one CVE, with package details",
)
async def cve_images(
    cve_id: str,
    response: Response,
    params: PageParams = Depends(page_params),
    not_modified: bool = Depends(apply_freshness),
    session: AsyncSession = Depends(get_session),
):
    if not_modified:
        return Response(status_code=304, headers=dict(response.headers))

    known = await session.scalar(select(func.count()).select_from(Cve).where(Cve.id == cve_id))
    if not known:
        raise HTTPException(status_code=404, detail=f"unknown CVE {cve_id}")

    conditions = [
        Finding.cve_id == cve_id,
        Finding.last_seen_run_id == Image.current_scan_run_id,
    ]

    total = (
        await session.scalar(
            select(func.count())
            .select_from(Finding)
            .join(Image, Image.id == Finding.image_id)
            .where(*conditions)
        )
    ) or 0

    rows = await session.execute(
        select(
            Image.name,
            Image.tag,
            ScanRun.digest,
            Finding.severity,
            Package.name,
            Package.version,
            Package.type,
            Finding.fixed_version,
            ScanRun.completed_at,
        )
        .join(Image, Image.id == Finding.image_id)
        .join(Package, Package.id == Finding.package_id)
        .join(ScanRun, ScanRun.id == Finding.last_seen_run_id)
        .where(*conditions)
        .order_by(Finding.severity_rank.desc(), Image.name, Image.tag)
        .limit(params.limit)
        .offset(params.offset)
    )

    items = [
        ImageAffectedByCve(
            name=name,
            tag=tag,
            digest=digest,
            severity=Severity(severity_value),
            package=PackageRef(name=pkg_name, version=pkg_version, type=pkg_type),
            fixed_version=fixed_version,
            last_seen_at=last_seen,
        )
        for (
            name,
            tag,
            digest,
            severity_value,
            pkg_name,
            pkg_version,
            pkg_type,
            fixed_version,
            last_seen,
        ) in rows
    ]

    return Page[ImageAffectedByCve](
        items=items,
        pagination=Pagination(total=total, limit=params.limit, offset=params.offset),
    )
