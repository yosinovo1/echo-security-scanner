"""SQLAlchemy models.

Identity note: an ``Image`` is keyed by ``(name, tag)`` because that is what the API
contract addresses, but a tag is a mutable pointer. The digest of the bytes actually
scanned is recorded on each ``ScanRun``, which is what makes findings reproducible,
makes tag drift observable, and makes the skip invariant in ``scanner.worker`` sound.
"""
from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.domain.severity import Severity


class Base(DeclarativeBase):
    pass


class JobStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class RunStatus(str, enum.Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


def _enum(py_enum: type[enum.Enum], name: str) -> Enum:
    # native_enum=False -> VARCHAR + CHECK, which keeps Alembic migrations boring.
    return Enum(
        py_enum,
        name=name,
        native_enum=False,
        values_callable=lambda e: [m.value for m in e],
        length=16,
    )


TS = DateTime(timezone=True)


class Image(Base):
    __tablename__ = "image"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    tag: Mapped[str] = mapped_column(String(128))

    #: NULL means "use settings.default_scan_interval_seconds".
    scan_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))

    #: The run whose findings are live. Deliberately NOT advanced by a skipped run:
    #: a skip means the previous run findings are still exactly right.
    current_scan_run_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    #: Consecutive *jobs* that ended exhausted, reset by any success or skip. Drives
    #: the per-image backoff in scheduler.next_due_at, and makes a rotting entry
    #: visible on GET /api/images rather than merely cheap.
    consecutive_failures: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    #: Denormalised from the most recent completed run of any kind, so that
    #: GET /api/images does not need a lateral join.
    last_scan_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_scan_status: Mapped[RunStatus | None] = mapped_column(
        _enum(RunStatus, "run_status"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("name", "tag", name="uq_image_name_tag"),
        CheckConstraint(
            "scan_interval_seconds IS NULL OR scan_interval_seconds > 0",
            name="ck_image_interval_positive",
        ),
    )

    @property
    def reference(self) -> str:
        return f"{self.name}:{self.tag}"


class ScanJob(Base):
    """Queue row. Claimed with SELECT ... FOR UPDATE SKIP LOCKED."""

    __tablename__ = "scan_job"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("image.id", ondelete="CASCADE"))
    status: Mapped[JobStatus] = mapped_column(
        _enum(JobStatus, "job_status"), server_default=JobStatus.PENDING.value
    )
    #: Higher first. Time-sensitive jobs are enqueued above the scheduled baseline;
    #: priority reorders work but never bypasses the content invariant, and never
    #: overrides a registry that is throttling us.
    priority: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    scheduled_for: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    lease_until: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())

    #: Lazy on purpose: the claim query uses FOR UPDATE SKIP LOCKED, and a joined
    #: eager load would put it on the nullable side of an outer join.
    image: Mapped[Image] = relationship(lazy="select")

    __table_args__ = (
        # Claim path: only pending rows are ever scanned by the worker query.
        Index(
            "ix_scan_job_claimable",
            text("priority DESC"),
            "scheduled_for",
            postgresql_where=text("status = 'pending'"),
        ),
        # Structurally prevents duplicate queueing for one image: the scheduler
        # cannot stampede, and a retry cannot double-enqueue.
        Index(
            "uq_scan_job_active",
            "image_id",
            unique=True,
            postgresql_where=text("status IN ('pending', 'running')"),
        ),
        Index(
            "ix_scan_job_lease",
            "lease_until",
            postgresql_where=text("status = 'running'"),
        ),
    )


class ScanRun(Base):
    """One scan attempt.

    This table is the "handle scan failures gracefully" deliverable, as queryable
    rows rather than log lines.
    """

    __tablename__ = "scan_run"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("image.id", ondelete="CASCADE"))
    scan_job_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    started_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    status: Mapped[RunStatus] = mapped_column(_enum(RunStatus, "run_status"))

    #: The four fields below form the skip invariant. If all match the previous
    #: successful run, the results are provably identical and Trivy is not invoked.
    digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trivy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trivy_db_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scan_flags_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: What this run found, by severity, denormalised so that GET /api/images does
    #: not aggregate the finding table. It is a fact *about this run*, immutable once
    #: written, and it commits in the same transaction as the findings it counts --
    #: so unlike a cache there is no window in which it can disagree with them.
    #:
    #: NULL rather than 0 on a failed or skipped run: those produce no finding set of
    #: their own, and a security tool must never render "we do not know" as "zero
    #: vulnerabilities". Only a successful run is ever read, because
    #: ``image.current_scan_run_id`` only ever points at one.
    finding_count_critical: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_count_high: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_count_medium: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_count_low: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_count_unknown: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index("ix_scan_run_image_completed", "image_id", text("completed_at DESC")),
        #: Serves the API freshness validator, which runs MAX(completed_at) over the
        #: whole table on every collection request. Leading with image_id above makes
        #: that index useless for it, so an unindexed scan of a table that only grows
        #: was being paid per request: measured 129ms at a 1000-image fleet's first
        #: month, 0.6ms with this.
        Index("ix_scan_run_completed", text("completed_at DESC")),
        #: /health asks the narrower question -- the newest run that actually
        #: produced findings.
        Index(
            "ix_scan_run_last_success",
            text("completed_at DESC"),
            postgresql_where=text("status = 'success'"),
        ),
    )


class Package(Base):
    __tablename__ = "package"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(255))
    #: Trivy PkgType: debian, alpine, ubuntu, python-pkg, node-pkg, ...
    type: Mapped[str] = mapped_column(String(64), server_default="unknown")

    __table_args__ = (UniqueConstraint("name", "version", "type", name="uq_package_nvt"),)


class Cve(Base):
    __tablename__ = "cve"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Derived rollup over *current* findings, recomputed after each scan.
    #: Rule: a CVE is CRITICAL if it is CRITICAL in any scanned image.
    max_severity: Mapped[Severity] = mapped_column(
        _enum(Severity, "severity"), server_default=Severity.UNKNOWN.value
    )
    max_severity_rank: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))

    #: How many scanned images currently carry this CVE. Derived alongside
    #: ``max_severity`` in the same recompute, so it costs nothing extra to maintain
    #: and it is what makes "is this CVE live?" an indexed predicate instead of an
    #: EXISTS over the whole finding table. Zero means every image that used to
    #: report it has stopped, so it drops out of GET /api/cves.
    affected_image_count: Mapped[int] = mapped_column(
        Integer, server_default=text("0")
    )

    published_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)

    __table_args__ = (
        Index("ix_cve_max_severity_rank", "max_severity_rank"),
        # GET /api/cves in its exact shape: live CVEs, worst first. Partial, so the
        # index holds only the CVEs any endpoint can return.
        Index(
            "ix_cve_live_by_severity",
            text("max_severity_rank DESC"),
            "id",
            postgresql_where=text("affected_image_count > 0"),
        ),
    )


class Finding(Base):
    """A CVE affecting a specific package in a specific image.

    A finding is *current* iff ``last_seen_run_id == image.current_scan_run_id``.
    Findings are never deleted: one that stops appearing simply stops having its
    ``last_seen_run_id`` advanced, which preserves the history the 15-minute cadence
    exists to produce.
    """

    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("image.id", ondelete="CASCADE"))
    cve_id: Mapped[str] = mapped_column(ForeignKey("cve.id", ondelete="CASCADE"))
    package_id: Mapped[int] = mapped_column(ForeignKey("package.id", ondelete="CASCADE"))

    fixed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"))
    severity_rank: Mapped[int] = mapped_column(SmallInteger)

    first_seen_run_id: Mapped[int] = mapped_column(BigInteger)
    last_seen_run_id: Mapped[int] = mapped_column(BigInteger)

    __table_args__ = (
        UniqueConstraint("image_id", "cve_id", "package_id", name="uq_finding_img_cve_pkg"),
        # GET /api/cves/:cve_id/images -- the inverted, cross-image query.
        Index("ix_finding_cve", "cve_id"),
        # GET /api/images/:name/:tag/cves?severity=
        Index("ix_finding_image_severity", "image_id", "severity_rank"),
        Index("ix_finding_last_seen", "last_seen_run_id"),
    )
