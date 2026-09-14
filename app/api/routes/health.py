"""Health check."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import Health
from app.db.session import get_session
from app.domain.models import Image, JobStatus, RunStatus, ScanJob, ScanRun

router = APIRouter(tags=["health"])


@router.get("/health", response_model=Health)
async def health(response: Response, session: AsyncSession = Depends(get_session)):
    """Liveness plus a little scanner state.

    Reports queue depth and last successful scan alongside connectivity, because an
    API that answers while no scan has succeeded for hours is not actually healthy.
    """
    try:
        images = await session.scalar(
            select(func.count()).select_from(Image).where(Image.enabled.is_(True))
        )
        pending = await session.scalar(
            select(func.count()).select_from(ScanJob).where(ScanJob.status == JobStatus.PENDING)
        )
        last_scan = await session.scalar(
            select(func.max(ScanRun.completed_at)).where(ScanRun.status == RunStatus.SUCCESS)
        )
    except Exception:
        response.status_code = 503
        return Health(status="degraded", database="unavailable")

    return Health(
        status="ok",
        database="ok",
        images_enabled=images or 0,
        jobs_pending=pending or 0,
        last_successful_scan_at=last_scan,
    )
