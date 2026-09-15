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


class QueueStats(BaseModel):
    pending: int = 0
    running: int = 0
    #: Jobs that exhausted their attempts. Non-zero means images are not being
    #: scanned, and the reasons are in `recent_failures`.
    failed: int = 0
    #: How long the oldest unclaimed job has been waiting past its scheduled time.
    #: The queue's backlog signal: it grows when workers cannot keep up with the
    #: scan cadence, where `pending` alone also grows harmlessly at every tick.
    oldest_pending_age_seconds: float | None = None


class ImageStats(BaseModel):
    total: int = 0
    enabled: int = 0
    never_scanned: int = 0
    #: Images with a non-zero failure streak, i.e. currently on a backed-off cadence.
    failing: int = 0


class RunOutcomes(BaseModel):
    """Scan attempts in the window, by outcome."""

    success: int = 0
    failed: int = 0
    skipped: int = 0
    #: Skips as a share of all attempts. High is healthy: it is the content invariant
    #: proving work unnecessary, which is where the scan budget is actually saved.
    skip_ratio: float = 0.0


class DurationStats(BaseModel):
    """Wall-clock scan time over successful runs in the window, in milliseconds."""

    count: int = 0
    p50: int | None = None
    p95: int | None = None
    max: int | None = None


class FailureReason(BaseModel):
    #: The exception class that ended the run. `scan_run.error` is written as
    #: "TypeName: message", so the class is recoverable without storing it twice.
    reason: str
    count: int


class Stats(BaseModel):
    """Operational statistics, derived from scan history rather than collected.

    Every number here is a query over rows the scanner already writes -- `scan_run`
    records one row per attempt with its outcome and duration, so it is the metrics
    store. Nothing is sampled, aggregated in memory, or lost on restart.
    """

    generated_at: datetime
    window_hours: int
    queue: QueueStats
    images: ImageStats
    runs: RunOutcomes
    scan_duration_ms: DurationStats
    recent_failures: list[FailureReason] = []
    #: Live findings across every image, read from the same per-run rollups that back
    #: GET /api/images rather than by aggregating `finding`.
    findings: SeverityCounts = SeverityCounts()
