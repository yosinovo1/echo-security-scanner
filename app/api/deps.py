"""Shared API dependencies: pagination and cache validators."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from email.utils import format_datetime

from fastapi import Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db.session import get_session
from app.domain.models import RunStatus, ScanRun
from app.domain.severity import FILTERABLE, Severity


@dataclass(frozen=True, slots=True)
class PageParams:
    limit: int
    offset: int


def page_params(
    limit: int | None = Query(default=None, ge=1, description="Defaults to 100."),
    offset: int = Query(default=0, ge=0),
    settings: Settings = Depends(get_settings),
) -> PageParams:
    effective = min(limit or settings.page_size_default, settings.page_size_max)
    return PageParams(limit=effective, offset=offset)


def severity_filter(
    severity: str | None = Query(
        default=None,
        description="Filter by severity: CRITICAL, HIGH, MEDIUM or LOW.",
    ),
) -> Severity | None:
    if severity is None:
        return None
    try:
        parsed = Severity(severity.strip().upper())
    except ValueError:
        parsed = None
    if parsed not in FILTERABLE:
        raise HTTPException(
            status_code=400,
            detail=f"severity must be one of {', '.join(s.value for s in FILTERABLE)}",
        )
    return parsed


async def apply_freshness(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> bool:
    """Set validators from the newest completed scan; report whether 304 applies.

    Correct by construction rather than by invalidation: the data can only change
    when a scan completes, so the newest completion timestamp *is* the version. This
    is the caching story without a cache to get stale.
    """
    newest = await session.scalar(
        select(func.max(ScanRun.completed_at)).where(ScanRun.status != RunStatus.FAILED)
    )
    if newest is None:
        return False

    stamp = int(newest.timestamp())
    etag = f'W/"{stamp}"'
    response.headers["ETag"] = etag
    response.headers["Last-Modified"] = format_datetime(
        newest.astimezone(UTC), usegmt=True
    )
    response.headers["Cache-Control"] = "public, max-age=30"

    return request.headers.get("if-none-match") == etag
