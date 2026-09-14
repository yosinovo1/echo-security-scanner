"""Response models.

The brief does not specify response shapes. Collections are wrapped in an envelope
so pagination metadata has somewhere to live; with the brief's ten images an
unparameterised request still returns everything in one page.
"""
from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

from app.domain.models import RunStatus
from app.domain.severity import Severity

T = TypeVar("T")


class Pagination(BaseModel):
    total: int
    limit: int
    offset: int


class Page(BaseModel, Generic[T]):
    items: list[T]
    pagination: Pagination


class SeverityCounts(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    UNKNOWN: int = 0

    @property
    def total(self) -> int:
        return self.CRITICAL + self.HIGH + self.MEDIUM + self.LOW + self.UNKNOWN


class ImageSummary(BaseModel):
    name: str
    tag: str
    #: Digest of the bytes the current findings describe. Null before the first
    #: successful scan.
    digest: str | None = None
    last_scan_at: datetime | None = None
    last_scan_status: RunStatus | None = None
    #: Consecutive failed jobs. Non-zero means this image is being scanned on a
    #: backed-off schedule, and a large value means the reference needs attention.
    consecutive_failures: int = 0
    scan_interval_seconds: int = Field(
        description="Effective interval, including the global default."
    )
    total_cves: int = 0
    severity_counts: SeverityCounts = SeverityCounts()


class PackageRef(BaseModel):
    name: str
    version: str
    type: str


class CveInImage(BaseModel):
    """A CVE as it appears in one image."""

    cve_id: str
    title: str | None = None
    #: Vendor severity for *this* image. The same CVE can be rated differently in a
    #: different distribution.
    severity: Severity
    package: PackageRef
    fixed_version: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class ImageAffectedByCve(BaseModel):
    """An image affected by a CVE, with the package that carries it."""

    name: str
    tag: str
    digest: str | None = None
    severity: Severity
    package: PackageRef
    fixed_version: str | None = None
    last_seen_at: datetime | None = None


class CveSummary(BaseModel):
    cve_id: str
    title: str | None = None
    #: Rollup across every scanned image: CRITICAL if CRITICAL anywhere.
    max_severity: Severity
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    affected_image_count: int = 0


class Health(BaseModel):
    status: str
    database: str
    images_enabled: int | None = None
    jobs_pending: int | None = None
    last_successful_scan_at: datetime | None = None


class ScanRequestAccepted(BaseModel):
    """Result of an out-of-band scan request."""

    status: str = Field(description="queued, promoted, or already_queued")
    job_id: int | None = None
    time_sensitive: bool = False
