"""Persistence invariants, against a real PostgreSQL.

These are the rules CLAUDE.md flags as corrupting results *silently* rather than
raising, which is exactly why they need tests: break one and the suite still passes,
the containers still start, and every affected image simply reports clean.

1. A finding is current iff ``last_seen_run_id == image.current_scan_run_id``.
2. A skipped run must NOT advance ``current_scan_run_id``.
3. ``cve.max_severity`` is a rollup over *current* findings, recomputed after the
   pointer moves.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text

from app.domain.models import Cve, Finding, Image, Package, RunStatus, ScanRun
from app.domain.severity import Severity
from app.scanner import persist
from app.scanner.parser import ParsedFinding, ParsedReport

pytestmark = pytest.mark.postgres


def cve_id() -> str:
    """A CVE id no other test can collide with, even if a rollback is skipped."""
    return f"CVE-9999-{uuid.uuid4().hex[:10]}"


def finding(
    cve: str,
    severity: Severity = Severity.HIGH,
    *,
    package: str = "openssl",
    version: str = "1.1.1",
    type_: str = "debian",
    fixed_version: str | None = "1.1.1a",
    title: str | None = "a title",
    description: str | None = "a description",
) -> ParsedFinding:
    return ParsedFinding(
        cve_id=cve,
        package_name=package,
        package_version=version,
        package_type=type_,
        severity=severity,
        fixed_version=fixed_version,
        title=title,
        description=description,
        published_at=None,
        last_modified_at=None,
    )


def report(*findings: ParsedFinding, digest: str = "sha256:aaa") -> ParsedReport:
    return ParsedReport(digest=digest, artifact_name="test:test", findings=findings)


def meta(digest: str | None = "sha256:aaa", *, seconds: int = 5) -> persist.RunMetadata:
    started = datetime.now(UTC)
    return persist.RunMetadata(
        digest=digest,
        trivy_version="0.58.1",
        trivy_db_version="2026-09-14T06:00:00Z",
        scan_flags_hash="abc123",
        started_at=started,
        completed_at=started + timedelta(seconds=seconds),
    )


def current_findings(session, image: Image) -> list[Finding]:
    return list(
        session.execute(
            select(Finding).where(
                Finding.image_id == image.id,
                Finding.last_seen_run_id == image.current_scan_run_id,
            )
        )
        .scalars()
        .all()
    )


def rollup(session, cve: str) -> Severity:
    return session.execute(select(Cve.max_severity).where(Cve.id == cve)).scalar_one()


class TestRecordSuccess:
    def test_findings_become_current_and_the_pointer_moves(self, session, image):
        cve = cve_id()
        run = persist.record_success(session, image, None, report(finding(cve)), meta())

        assert image.current_scan_run_id == run.id
        assert image.last_scan_status == RunStatus.SUCCESS
        (stored,) = current_findings(session, image)
        assert stored.cve_id == cve
        assert stored.first_seen_run_id == stored.last_seen_run_id == run.id

    def test_duration_is_recorded_from_the_metadata(self, session, image):
        run = persist.record_success(
            session, image, None, report(finding(cve_id())), meta(seconds=7)
        )
        assert run.duration_ms == 7000

    def test_package_identity_includes_the_ecosystem(self, session, image):
        # openssl-the-Debian-package and openssl-the-Python-package are not the same
        # thing, and must not collapse onto one row.
        cve = cve_id()
        persist.record_success(
            session,
            image,
            None,
            report(
                finding(cve, package="openssl", version="1.1.1", type_="debian"),
                finding(cve, package="openssl", version="1.1.1", type_="python-pkg"),
            ),
            meta(),
        )
        packages = (
            session.execute(
                select(Package).where(Package.name == "openssl", Package.version == "1.1.1")
            )
            .scalars()
            .all()
        )
        assert {p.type for p in packages} == {"debian", "python-pkg"}
        assert len(current_findings(session, image)) == 2


class TestCurrencyInvariant:
    """Invariant 1: currency is a pointer comparison, never a delete."""

    def test_a_finding_that_stops_being_reported_stops_being_current(self, session, image):
        gone, stays = cve_id(), cve_id()
        persist.record_success(
            session, image, None, report(finding(gone), finding(stays)), meta()
        )
        persist.record_success(
            session,
            image,
            None,
            report(finding(stays), digest="sha256:bbb"),
            meta("sha256:bbb"),
        )

        assert {f.cve_id for f in current_findings(session, image)} == {stays}

    def test_but_it_is_not_deleted(self, session, image):
        gone = cve_id()
        persist.record_success(session, image, None, report(finding(gone)), meta())
        persist.record_success(
            session, image, None, report(digest="sha256:bbb"), meta("sha256:bbb")
        )

        # Still on disk as history: the 15-minute cadence exists to produce exactly
        # this record of when a vulnerability was present and when it stopped being.
        survivor = session.execute(
            select(Finding).where(Finding.image_id == image.id, Finding.cve_id == gone)
        ).scalar_one()
        assert survivor.last_seen_run_id != image.current_scan_run_id

    def test_first_seen_survives_every_later_sighting(self, session, image):
        cve = cve_id()
        first = persist.record_success(session, image, None, report(finding(cve)), meta())
        second = persist.record_success(
            session, image, None, report(finding(cve), digest="sha256:bbb"), meta("sha256:bbb")
        )

        (stored,) = current_findings(session, image)
        assert stored.first_seen_run_id == first.id
        assert stored.last_seen_run_id == second.id

    def test_a_reappearing_finding_keeps_its_original_first_seen(self, session, image):
        cve = cve_id()
        first = persist.record_success(session, image, None, report(finding(cve)), meta())
        persist.record_success(
            session, image, None, report(digest="sha256:bbb"), meta("sha256:bbb")
        )
        persist.record_success(
            session, image, None, report(finding(cve), digest="sha256:ccc"), meta("sha256:ccc")
        )

        (stored,) = current_findings(session, image)
        assert stored.first_seen_run_id == first.id

    def test_severity_is_updated_in_place_on_a_later_sighting(self, session, image):
        cve = cve_id()
        persist.record_success(session, image, None, report(finding(cve, Severity.LOW)), meta())
        persist.record_success(
            session,
            image,
            None,
            report(finding(cve, Severity.CRITICAL), digest="sha256:bbb"),
            meta("sha256:bbb"),
        )
        (stored,) = current_findings(session, image)
        assert stored.severity == Severity.CRITICAL


class TestSkipInvariant:
    """Invariant 2: a skip means the previous findings are still exactly right."""

    def test_skip_does_not_advance_the_current_run_pointer(self, session, image):
        scanned = persist.record_success(
            session, image, None, report(finding(cve_id())), meta()
        )
        skipped = persist.record_skip(session, image, None, meta(), reason="unchanged")

        assert skipped.id != scanned.id
        # The whole invariant in one line: repointing here would strand every finding
        # the previous run produced and make the image look clean.
        assert image.current_scan_run_id == scanned.id

    def test_findings_stay_current_across_a_skip(self, session, image):
        cve = cve_id()
        persist.record_success(session, image, None, report(finding(cve)), meta())
        persist.record_skip(session, image, None, meta(), reason="unchanged")

        assert {f.cve_id for f in current_findings(session, image)} == {cve}

    def test_skip_still_records_the_attempt_and_moves_last_scan_at(self, session, image):
        persist.record_success(session, image, None, report(finding(cve_id())), meta())
        before = image.last_scan_at
        skipped = persist.record_skip(session, image, None, meta(), reason="unchanged")

        assert skipped.status == RunStatus.SKIPPED
        assert image.last_scan_status == RunStatus.SKIPPED
        assert image.last_scan_at >= before

    def test_a_skip_does_not_disturb_the_rollup(self, session, image):
        cve = cve_id()
        persist.record_success(
            session, image, None, report(finding(cve, Severity.CRITICAL)), meta()
        )
        persist.record_skip(session, image, None, meta(), reason="unchanged")
        assert rollup(session, cve) == Severity.CRITICAL


class TestFailureIsolation:
    def test_a_failure_leaves_the_last_good_findings_current(self, session, image):
        cve = cve_id()
        good = persist.record_success(session, image, None, report(finding(cve)), meta())
        persist.record_failure(session, image, None, meta(digest=None), error="boom")

        assert image.current_scan_run_id == good.id
        assert {f.cve_id for f in current_findings(session, image)} == {cve}
        assert image.last_scan_status == RunStatus.FAILED

    def test_an_exhausted_job_extends_the_failure_streak(self, session, image):
        for expected in (1, 2, 3):
            persist.record_failure(
                session, image, None, meta(digest=None), error="gone", exhausted=True
            )
            assert image.consecutive_failures == expected

    def test_a_failed_attempt_that_will_be_retried_does_not_count(self, session, image):
        # The job backs off across its own retries; counting every attempt would let
        # one transient blip push a healthy image onto a multi-hour cadence.
        for _ in range(5):
            persist.record_failure(
                session, image, None, meta(digest=None), error="flaky", exhausted=False
            )
        assert image.consecutive_failures == 0

    def test_a_success_clears_the_streak(self, session, image):
        persist.record_failure(
            session, image, None, meta(digest=None), error="gone", exhausted=True
        )
        persist.record_success(session, image, None, report(finding(cve_id())), meta())
        assert image.consecutive_failures == 0

    def test_a_skip_clears_the_streak_too(self, session, image):
        # A skip means the digest resolved and nothing changed, which is proof the
        # image is reachable -- exactly as healthy as a success for this purpose.
        persist.record_failure(
            session, image, None, meta(digest=None), error="gone", exhausted=True
        )
        persist.record_skip(session, image, None, meta(), reason="unchanged")
        assert image.consecutive_failures == 0

    def test_the_error_is_stored_as_a_queryable_row(self, session, image):
        persist.record_failure(session, image, None, meta(digest=None), error="trivy exploded")
        run = session.execute(
            select(ScanRun).where(
                ScanRun.image_id == image.id, ScanRun.status == RunStatus.FAILED
            )
        ).scalar_one()
        assert "trivy exploded" in run.error


class TestSeverityRollup:
    """Invariant 3: a derived MAX over *current* findings, never a per-image rating."""

    def test_rollup_takes_the_highest_severity_across_images(self, session, image, other_image):
        cve = cve_id()
        persist.record_success(
            session, image, None, report(finding(cve, Severity.MEDIUM)), meta()
        )
        assert rollup(session, cve) == Severity.MEDIUM

        persist.record_success(
            session, other_image, None, report(finding(cve, Severity.CRITICAL)), meta()
        )
        # Distros rate the same CVE differently; CRITICAL anywhere wins.
        assert rollup(session, cve) == Severity.CRITICAL

    def test_rollup_drops_when_the_critical_image_stops_reporting_it(
        self, session, image, other_image
    ):
        cve = cve_id()
        persist.record_success(
            session, image, None, report(finding(cve, Severity.MEDIUM)), meta()
        )
        persist.record_success(
            session, other_image, None, report(finding(cve, Severity.CRITICAL)), meta()
        )
        assert rollup(session, cve) == Severity.CRITICAL

        # The CRITICAL sighting is now history, so it must stop counting. This is the
        # test that fails if the rollup is recomputed before the pointer moves.
        persist.record_success(
            session, other_image, None, report(digest="sha256:bbb"), meta("sha256:bbb")
        )
        assert rollup(session, cve) == Severity.MEDIUM

    def test_rollup_falls_to_unknown_when_nothing_reports_it_any_more(self, session, image):
        cve = cve_id()
        persist.record_success(session, image, None, report(finding(cve, Severity.HIGH)), meta())
        persist.record_success(
            session, image, None, report(digest="sha256:bbb"), meta("sha256:bbb")
        )
        assert rollup(session, cve) == Severity.UNKNOWN

    def test_rank_and_name_stay_in_step(self, session, image):
        cve = cve_id()
        persist.record_success(
            session, image, None, report(finding(cve, Severity.CRITICAL)), meta()
        )
        row = session.execute(select(Cve).where(Cve.id == cve)).scalar_one()
        assert (row.max_severity, row.max_severity_rank) == (Severity.CRITICAL, 4)


class TestCveDescriptions:
    def test_a_later_scan_that_omits_a_description_does_not_erase_it(self, session, image):
        cve = cve_id()
        persist.record_success(
            session, image, None, report(finding(cve, description="the real detail")), meta()
        )
        persist.record_success(
            session,
            image,
            None,
            report(finding(cve, description=None, title=None), digest="sha256:bbb"),
            meta("sha256:bbb"),
        )

        row = session.execute(select(Cve).where(Cve.id == cve)).scalar_one()
        assert row.description == "the real detail"
        assert row.title == "a title"

    def test_fields_arrive_independently_across_scans(self, session, image):
        """The case that keeps the COALESCE honest once the write guard exists.

        The guard fires when *any* descriptive field is fillable, but the SET touches
        all four -- so a scan that supplies only the description would blank a title
        an earlier scan had already learned. Different distributions genuinely report
        different subsets of these fields for the same CVE, so this is the ordinary
        case, not a contrived one.
        """
        cve = cve_id()
        persist.record_success(
            session,
            image,
            None,
            report(finding(cve, title="known title", description=None)),
            meta(),
        )
        persist.record_success(
            session,
            image,
            None,
            report(
                finding(cve, title=None, description="learned later"),
                digest="sha256:bbb",
            ),
            meta("sha256:bbb"),
        )

        row = session.execute(select(Cve).where(Cve.id == cve)).scalar_one()
        assert row.title == "known title"
        assert row.description == "learned later"

    def test_the_same_cve_from_two_packages_is_stored_once(self, session, image):
        cve = cve_id()
        persist.record_success(
            session,
            image,
            None,
            report(
                finding(cve, package="libssl", version="1.0"),
                finding(cve, package="libcrypto", version="1.0"),
            ),
            meta(),
        )
        rows = session.execute(select(Cve).where(Cve.id == cve)).scalars().all()
        assert len(rows) == 1
        assert len(current_findings(session, image)) == 2


class TestAffectedImageCount:
    """``cve.affected_image_count`` decides whether a CVE appears in GET /api/cves.

    It replaces an EXISTS over the finding table, so if it drifts high the API lists
    a CVE nothing carries any more, and if it drifts low a live vulnerability
    disappears from the listing. The second is the one that matters.
    """

    def count(self, session, cve: str) -> int:
        return session.execute(
            select(Cve.affected_image_count).where(Cve.id == cve)
        ).scalar_one()

    def test_counts_the_images_currently_reporting_it(self, session, image, other_image):
        shared = cve_id()
        persist.record_success(session, image, None, report(finding(shared)), meta())
        assert self.count(session, shared) == 1

        persist.record_success(session, other_image, None, report(finding(shared)), meta())
        assert self.count(session, shared) == 2

    def test_the_same_cve_from_two_packages_in_one_image_counts_once(self, session, image):
        cve = cve_id()
        persist.record_success(
            session,
            image,
            None,
            report(
                finding(cve, package="libssl", version="1.0"),
                finding(cve, package="libcrypto", version="1.0"),
            ),
            meta(),
        )
        # It counts *images*, not findings -- one image with two vulnerable packages
        # is still one affected image.
        assert self.count(session, cve) == 1

    def test_it_drops_when_an_image_stops_reporting_the_cve(
        self, session, image, other_image
    ):
        shared, replacement = cve_id(), cve_id()
        persist.record_success(session, image, None, report(finding(shared)), meta())
        persist.record_success(session, other_image, None, report(finding(shared)), meta())

        persist.record_success(
            session, image, None, report(finding(replacement), digest="sha256:bbb"), meta("sha256:bbb")
        )
        assert self.count(session, shared) == 1

    def test_it_reaches_zero_so_the_cve_leaves_the_listing(self, session, image):
        cve = cve_id()
        persist.record_success(session, image, None, report(finding(cve)), meta())
        persist.record_success(
            session, image, None, report(digest="sha256:bbb"), meta("sha256:bbb")
        )
        assert self.count(session, cve) == 0

    def test_a_skip_does_not_disturb_it(self, session, image):
        cve = cve_id()
        persist.record_success(session, image, None, report(finding(cve)), meta())
        persist.record_skip(session, image, None, meta(), reason="unchanged")
        # A skip leaves current_scan_run_id alone, so the findings -- and the count
        # derived from them -- are still exactly right.
        assert self.count(session, cve) == 1


class TestDenormalisedCounts:
    """The counts on ``scan_run`` must never disagree with the findings they describe.

    They exist so ``GET /api/images`` does not aggregate the finding table, which is
    the one denormalisation in the schema that could silently understate how
    vulnerable an image is. Written in the same transaction as the findings, so the
    only way they drift is a code change -- which is what this class is here to fail.
    """

    def _counts(self, run: ScanRun) -> dict[Severity, int]:
        return {
            severity: getattr(run, f"finding_count_{severity.value.lower()}")
            for severity in Severity
        }

    def test_counts_match_the_findings_the_run_made_current(self, session, image):
        run = persist.record_success(
            session,
            image,
            None,
            report(
                finding(cve_id(), Severity.CRITICAL),
                finding(cve_id(), Severity.HIGH, package="zlib"),
                finding(cve_id(), Severity.HIGH, package="curl"),
                finding(cve_id(), Severity.LOW, package="bash"),
            ),
            meta(),
        )
        counted = self._counts(run)
        assert counted[Severity.CRITICAL] == 1
        assert counted[Severity.HIGH] == 2
        assert counted[Severity.LOW] == 1
        assert sum(counted.values()) == len(current_findings(session, image))

    def test_a_clean_image_counts_zero_rather_than_null(self, session, image):
        run = persist.record_success(session, image, None, report(), meta())
        assert self._counts(run) == dict.fromkeys(Severity, 0)

    def test_counts_follow_a_rescan_downwards(self, session, image):
        first = cve_id()
        persist.record_success(
            session, image, None, report(finding(first, Severity.CRITICAL)), meta()
        )
        second = persist.record_success(
            session, image, None, report(finding(first, Severity.LOW)), meta()
        )
        assert second.finding_count_critical == 0
        assert second.finding_count_low == 1

    @pytest.mark.parametrize("recorder", ["failure", "skip"])
    def test_a_run_that_produced_no_findings_has_no_counts_at_all(
        self, session, image, recorder
    ):
        # NULL, not 0: neither outcome produced a finding set, and a security tool
        # must never render "we do not know" as "zero vulnerabilities".
        if recorder == "failure":
            run = persist.record_failure(session, image, None, meta(None), error="boom")
        else:
            run = persist.record_skip(session, image, None, meta(), reason="unchanged")
        assert self._counts(run) == dict.fromkeys(Severity, None)


class TestRollupWriteAmplification:
    def test_an_unchanged_rollup_does_not_rewrite_the_row(self, session, image):
        """Every successful scan recomputes the rollup for every CVE in the image.

        Almost none have changed rank, so without the IS DISTINCT FROM guard a single
        scan rewrites thousands of rows to the values they already held -- dead row
        versions and WAL for no change, and a wider window for two workers to collide
        on images that share CVEs. ``ctid`` is the row's physical location and
        moves on any update, including one inside the transaction that wrote it --
        which ``xmin`` would not show, since it is per transaction, not per write.
        """
        cve = cve_id()
        persist.record_success(session, image, None, report(finding(cve, Severity.HIGH)), meta())
        session.flush()
        before = session.execute(
            select(text("ctid::text")).select_from(Cve).where(Cve.id == cve)
        ).scalar_one()

        persist.record_success(session, image, None, report(finding(cve, Severity.HIGH)), meta())
        session.flush()
        after = session.execute(
            select(text("ctid::text")).select_from(Cve).where(Cve.id == cve)
        ).scalar_one()

        assert after == before

    def test_but_a_changed_rollup_is_written(self, session, image):
        cve = cve_id()
        persist.record_success(session, image, None, report(finding(cve, Severity.LOW)), meta())
        session.flush()
        before = session.execute(
            select(text("ctid::text")).select_from(Cve).where(Cve.id == cve)
        ).scalar_one()

        persist.record_success(
            session, image, None, report(finding(cve, Severity.CRITICAL)), meta()
        )
        session.flush()
        after = session.execute(
            select(text("ctid::text")).select_from(Cve).where(Cve.id == cve)
        ).scalar_one()

        assert after != before
        assert rollup(session, cve) == Severity.CRITICAL
