"""Write a scan result.

Everything here runs inside the caller's transaction, alongside the job's state
change, so a scan's findings and its completion are committed or lost together.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import String, and_, bindparam, func, or_, select, text, tuple_
from sqlalchemy.dialects.postgresql import ARRAY, insert
from sqlalchemy.orm import Session

from app.domain.models import Cve, Finding, Image, Package, RunStatus, ScanJob, ScanRun
from app.domain.severity import SEVERITY_RANK, Severity, rank
from app.scanner.parser import ParsedReport

# Rank -> name, so the rollup can be a single UPDATE instead of a read/modify/write.
_RANK_CASE = " ".join(f"WHEN {r} THEN '{s.value}'" for s, r in SEVERITY_RANK.items())


@dataclass(frozen=True, slots=True)
class RunMetadata:
    """The four invariant fields plus timing."""

    digest: str | None
    trivy_version: str | None
    trivy_db_version: str | None
    scan_flags_hash: str | None
    started_at: datetime
    completed_at: datetime

    @property
    def duration_ms(self) -> int:
        return int((self.completed_at - self.started_at).total_seconds() * 1000)


def _new_run(
    image: Image, job: ScanJob | None, status: RunStatus, meta: RunMetadata, error: str | None
) -> ScanRun:
    return ScanRun(
        image_id=image.id,
        scan_job_id=job.id if job else None,
        started_at=meta.started_at,
        completed_at=meta.completed_at,
        status=status,
        digest=meta.digest,
        trivy_version=meta.trivy_version,
        trivy_db_version=meta.trivy_db_version,
        scan_flags_hash=meta.scan_flags_hash,
        duration_ms=meta.duration_ms,
        error=error,
    )


def _current_cve_ids(session: Session, image: Image) -> set[str]:
    if image.current_scan_run_id is None:
        return set()
    rows = session.execute(
        select(Finding.cve_id).where(
            Finding.image_id == image.id,
            Finding.last_seen_run_id == image.current_scan_run_id,
        )
    ).scalars()
    return set(rows)


def _upsert_packages(
    session: Session, report: ParsedReport
) -> dict[tuple[str, str, str], int]:
    keys = sorted(
        {(f.package_name, f.package_version, f.package_type) for f in report.findings}
    )
    if not keys:
        return {}

    session.execute(
        insert(Package)
        .values([{"name": n, "version": v, "type": t} for n, v, t in keys])
        .on_conflict_do_nothing(constraint="uq_package_nvt")
    )
    rows = session.execute(
        select(Package.id, Package.name, Package.version, Package.type).where(
            tuple_(Package.name, Package.version, Package.type).in_(keys)
        )
    ).all()
    return {(name, version, type_): pkg_id for pkg_id, name, version, type_ in rows}


def _upsert_cves(session: Session, report: ParsedReport) -> None:
    by_id: dict[str, dict] = {}
    for finding in report.findings:
        # Same CVE can arrive from several packages; the descriptive fields are
        # identical, so first non-null wins.
        current = by_id.setdefault(
            finding.cve_id,
            {
                "id": finding.cve_id,
                "title": None,
                "description": None,
                "published_at": None,
                "last_modified_at": None,
            },
        )
        for field in ("title", "description", "published_at", "last_modified_at"):
            if current[field] is None:
                current[field] = getattr(finding, field)

    if not by_id:
        return

    statement = insert(Cve).values(list(by_id.values()))
    descriptive = ("title", "description", "published_at", "last_modified_at")
    session.execute(
        statement.on_conflict_do_update(
            index_elements=[Cve.id],
            # COALESCE so a later scan that omits a description does not erase one.
            set_={
                field: func.coalesce(
                    getattr(statement.excluded, field), getattr(Cve, field)
                )
                for field in descriptive
            },
            # Given that COALESCE, the row only changes when this scan fills in a
            # field we were missing -- so write only then. Every CVE in the image
            # reaches here on every successful scan, and a CVE's description does not
            # change between two scans fifteen minutes apart: without this, a rescan
            # rewrites thousands of rows to the values they already held. Same
            # argument as the rollup below, and both are needed, since either one
            # alone still rewrites the row.
            where=or_(
                *(
                    and_(
                        getattr(Cve, field).is_(None),
                        getattr(statement.excluded, field).is_not(None),
                    )
                    for field in descriptive
                )
            ),
        )
    )


def _upsert_findings(
    session: Session,
    image: Image,
    report: ParsedReport,
    package_ids: dict[tuple[str, str, str], int],
    run_id: int,
) -> dict[Severity, int]:
    """Write the findings and return what was written, counted by severity.

    Counted from the rows actually inserted rather than from ``report.findings``, so
    the denormalised totals on ``scan_run`` can never describe rows that did not
    reach the table.
    """
    rows = []
    for finding in report.findings:
        package_id = package_ids.get(
            (finding.package_name, finding.package_version, finding.package_type)
        )
        if package_id is None:  # pragma: no cover - only if the upsert above lost a row
            continue
        rows.append(
            {
                "image_id": image.id,
                "cve_id": finding.cve_id,
                "package_id": package_id,
                "fixed_version": finding.fixed_version,
                "severity": finding.severity.value,
                "severity_rank": rank(finding.severity),
                "first_seen_run_id": run_id,
                "last_seen_run_id": run_id,
            }
        )
    counts = Counter(Severity(row["severity"]) for row in rows)
    if not rows:
        return dict(counts)

    statement = insert(Finding).values(rows)
    session.execute(
        statement.on_conflict_do_update(
            constraint="uq_finding_img_cve_pkg",
            # first_seen_run_id is deliberately absent: it records when the finding
            # first appeared and must survive every later sighting.
            set_={
                "fixed_version": statement.excluded.fixed_version,
                "severity": statement.excluded.severity,
                "severity_rank": statement.excluded.severity_rank,
                "last_seen_run_id": statement.excluded.last_seen_run_id,
            },
        )
    )
    return dict(counts)


def _recompute_cve_rollup(session: Session, cve_ids: set[str]) -> None:
    """Recompute ``cve.max_severity`` over *current* findings only.

    Recomputes both derived columns on ``cve``: ``max_severity`` and
    ``affected_image_count``. They come from the same GROUP BY over current findings,
    so maintaining the second costs nothing over the first -- and it is what lets
    ``GET /api/cves`` filter on an indexed column instead of running an EXISTS over
    the whole finding table per CVE.

    Must run after ``image.current_scan_run_id`` has been advanced, since that column
    is what defines which findings count.

    The ``IS DISTINCT FROM`` guard is load-bearing at scale, not a micro-optimisation.
    Every successful scan reaches here with every CVE in the image -- roughly two
    thousand of them -- and almost none have actually changed rank, so without it a
    single scan rewrites two thousand rows to the values they already held.

    Measured with eight concurrent scanners over 400 shared CVEs, six rounds each:
    38,000 dead tuples and a 2.9 MB table against 400 live rows, versus 0 dead tuples
    and 168 kB with the guard in place. It is table bloat and WAL for no change.
    (It does *not* cause deadlocks -- that was worth checking, and neither variant
    produced one; the cost is purely churn.)
    """
    if not cve_ids:
        return

    statement = text(
        f"""
        UPDATE cve
           SET max_severity_rank = COALESCE(sub.rank, 0),
               max_severity = CASE COALESCE(sub.rank, 0) {_RANK_CASE} ELSE 'UNKNOWN' END,
               affected_image_count = COALESCE(sub.images, 0)
          FROM unnest(:ids) AS ids(cve_id)
          LEFT JOIN (
                SELECT f.cve_id,
                       MAX(f.severity_rank) AS rank,
                       COUNT(DISTINCT f.image_id) AS images
                  FROM finding f
                  JOIN image i ON i.id = f.image_id
                 WHERE f.last_seen_run_id = i.current_scan_run_id
                   AND f.cve_id = ANY(:ids)
                 GROUP BY f.cve_id
          ) sub ON sub.cve_id = ids.cve_id
         WHERE cve.id = ids.cve_id
           AND (cve.max_severity_rank IS DISTINCT FROM COALESCE(sub.rank, 0)
                OR cve.affected_image_count IS DISTINCT FROM COALESCE(sub.images, 0))
        """
    ).bindparams(bindparam("ids", value=sorted(cve_ids), type_=ARRAY(String)))
    session.execute(statement)


def record_success(
    session: Session,
    image: Image,
    job: ScanJob | None,
    report: ParsedReport,
    meta: RunMetadata,
) -> ScanRun:
    # Captured before the pointer moves: a CVE that vanished from this image still
    # needs its rollup recomputed.
    affected = _current_cve_ids(session, image) | {f.cve_id for f in report.findings}

    run = _new_run(image, job, RunStatus.SUCCESS, meta, error=None)
    session.add(run)
    session.flush()

    package_ids = _upsert_packages(session, report)
    _upsert_cves(session, report)
    counts = _upsert_findings(session, image, report, package_ids, run.id)

    for severity in Severity:
        setattr(run, f"finding_count_{severity.value.lower()}", counts.get(severity, 0))

    image.current_scan_run_id = run.id
    image.last_scan_at = meta.completed_at
    image.last_scan_status = RunStatus.SUCCESS
    image.consecutive_failures = 0
    session.flush()

    _recompute_cve_rollup(session, affected)
    return run


def record_skip(
    session: Session, image: Image, job: ScanJob | None, meta: RunMetadata, reason: str
) -> ScanRun:
    """Record a provably-unnecessary scan.

    ``current_scan_run_id`` is intentionally left alone: the previous run's findings
    are still exactly right, and repointing it would strand every one of them.
    """
    run = _new_run(image, job, RunStatus.SKIPPED, meta, error=None)
    session.add(run)
    session.flush()

    image.last_scan_at = meta.completed_at
    image.last_scan_status = RunStatus.SKIPPED
    # A skip means the digest resolved and nothing had changed, so the image is
    # demonstrably healthy -- it clears the failure streak exactly like a success.
    image.consecutive_failures = 0
    session.flush()
    return run


def record_failure(
    session: Session,
    image: Image,
    job: ScanJob | None,
    meta: RunMetadata,
    error: str,
    *,
    exhausted: bool = False,
) -> ScanRun:
    """Record a failed attempt without disturbing the last good findings.

    ``exhausted`` says the *job* gave up, not merely that this attempt failed. The
    failure streak counts jobs rather than attempts because a job already backs off
    across its own retries: counting every attempt would let one transient registry
    blip burn five retries in eight minutes and push a perfectly healthy image onto a
    multi-hour cadence.
    """
    run = _new_run(image, job, RunStatus.FAILED, meta, error=error[:4000])
    session.add(run)
    session.flush()

    image.last_scan_at = meta.completed_at
    image.last_scan_status = RunStatus.FAILED
    if exhausted:
        image.consecutive_failures = (image.consecutive_failures or 0) + 1
    session.flush()
    return run
