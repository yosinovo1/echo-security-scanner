"""Scheduler behaviour: due-time arithmetic, the skip invariant, lease configuration.

Most of this is pure logic needing no database and no network, so it runs everywhere.
The exception is ``TestReapingDeadWorkers`` at the end, which needs real rows.
Registry reference parsing lives in ``test_registry.py`` with the rest of the client.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.domain.models import Image, JobStatus, RunStatus, ScanJob, ScanRun
from app.jobs import queue
from app.scanner.worker import _is_unchanged
from app.scheduler.scheduler import next_due_at, tick

#: The default failure-backoff ceiling, spelled out so the arithmetic below reads.
DAY = 86400


class TestNextDue:
    def _image(self, **kwargs) -> Image:
        image = Image(name="nginx", tag="1.19")
        image.id = kwargs.pop("id", 1)
        image.created_at = kwargs.pop("created_at", datetime(2026, 1, 1, tzinfo=UTC))
        image.last_scan_at = kwargs.pop("last_scan_at", None)
        image.scan_interval_seconds = kwargs.pop("scan_interval_seconds", None)
        image.consecutive_failures = kwargs.pop("consecutive_failures", 0)
        return image

    def test_never_scanned_image_is_due_immediately(self):
        # No cold-start jitter: the queue bounds concurrency, so delaying the enqueue
        # would only delay the first results. A newly added image scans on the next
        # tick rather than after a spread window.
        image = self._image()
        assert next_due_at(image, 900, max_failure_backoff=DAY) == image.created_at

    def test_scanned_image_is_due_one_interval_after_the_last_scan(self):
        last = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        image = self._image(last_scan_at=last)
        assert next_due_at(image, 900, max_failure_backoff=DAY) == last + timedelta(
            seconds=900
        )

    def test_per_image_interval_overrides_the_global_default(self):
        last = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        image = self._image(last_scan_at=last, scan_interval_seconds=60)
        assert next_due_at(image, 900, max_failure_backoff=DAY) == last + timedelta(
            seconds=60
        )


class TestFailureBackoff:
    """An image whose jobs keep failing must not be retried on the dot forever.

    queue.fail already backs off within a job. Without the same thing per image, a
    reference deleted from its registry costs ninety-six requests a day indefinitely
    for an answer that cannot change.
    """

    def _image(self, failures: int) -> Image:
        image = Image(name="nginx", tag="1.19")
        image.id = 1
        image.created_at = datetime(2026, 1, 1, tzinfo=UTC)
        image.last_scan_at = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        image.scan_interval_seconds = None
        image.consecutive_failures = failures
        return image

    def _delay(self, failures: int, *, cap: int = DAY) -> int:
        image = self._image(failures)
        return int(
            (next_due_at(image, 900, max_failure_backoff=cap) - image.last_scan_at)
            .total_seconds()
        )

    def test_a_healthy_image_keeps_the_plain_interval(self):
        assert self._delay(0) == 900

    @pytest.mark.parametrize(
        "failures,seconds", [(1, 1800), (2, 3600), (3, 7200), (4, 14400)]
    )
    def test_each_consecutive_failure_doubles_the_wait(self, failures, seconds):
        assert self._delay(failures) == seconds

    def test_backoff_is_capped(self):
        # Without a ceiling this overflows into geological time within a fortnight.
        assert self._delay(20) == DAY
        assert self._delay(50) == DAY

    def test_the_cap_is_configurable(self):
        assert self._delay(20, cap=3600) == 3600

    def test_a_dead_reference_settles_at_roughly_one_attempt_a_day(self):
        # The whole point: 96 requests a day becomes 1, without anyone intervening.
        assert self._delay(7) == DAY

    def test_a_never_scanned_image_is_unaffected_by_the_streak(self):
        # consecutive_failures cannot be meaningful before the first attempt, and a
        # newly added image must still scan immediately.
        image = self._image(5)
        image.last_scan_at = None
        assert next_due_at(image, 900, max_failure_backoff=DAY) == image.created_at


class TestSkipInvariant:
    """Identical bytes, scanner, database and flags cannot yield different findings."""

    def _run(self, **overrides) -> ScanRun:
        defaults = {
            "digest": "sha256:aaa",
            "trivy_version": "0.58.1",
            "trivy_db_version": "2026-09-14T06:00:00Z",
            "scan_flags_hash": "abc123",
            "status": RunStatus.SUCCESS,
        }
        return ScanRun(**{**defaults, **overrides})

    ARGS = ("sha256:aaa", "0.58.1", "2026-09-14T06:00:00Z", "abc123")

    def test_all_four_matching_means_skip(self):
        assert _is_unchanged(self._run(), *self.ARGS) is True

    def test_no_previous_run_never_skips(self):
        assert _is_unchanged(None, *self.ARGS) is False

    def test_new_digest_forces_a_scan(self):
        assert _is_unchanged(self._run(digest="sha256:bbb"), *self.ARGS) is False

    def test_new_vulnerability_database_forces_a_scan(self):
        # The case a "scanned recently" heuristic gets wrong: nothing about the image
        # changed, but the database did, so the answer may well have changed.
        stale = self._run(trivy_db_version="2026-09-13T06:00:00Z")
        assert _is_unchanged(stale, *self.ARGS) is False

    def test_new_scanner_version_forces_a_scan(self):
        assert _is_unchanged(self._run(trivy_version="0.57.0"), *self.ARGS) is False

    def test_changed_flags_force_a_scan(self):
        assert _is_unchanged(self._run(scan_flags_hash="deadbeef"), *self.ARGS) is False

    def test_unresolved_previous_digest_does_not_match(self):
        assert _is_unchanged(self._run(digest=None), *self.ARGS) is False


class TestLeaseConfiguration:
    """A lease that expires mid-scan would let two workers scan the same image."""

    def test_default_lease_outlives_a_scan(self):
        settings = Settings()
        assert settings.lease_seconds > settings.trivy_timeout_seconds

    def test_a_lease_shorter_than_the_scan_timeout_is_rejected(self):
        with pytest.raises(ValidationError, match="must exceed"):
            Settings(lease_seconds=300, trivy_timeout_seconds=900)


class TestReapingDeadWorkers:
    """What happens to a job whose worker stopped reporting.

    A worker killed mid-scan -- OOM on a large image, a Trivy crash, an evicted node
    -- never reaches its own error handling, so the scheduler is the only process
    left to account for the attempt. If it does not, that attempt is the one failure
    in the system that leaves no trace and costs nothing, which is exactly the
    combination that lets a job retry forever.
    """

    pytestmark = pytest.mark.postgres

    @pytest.fixture
    def settings(self) -> Settings:
        return Settings()

    def _strand(self, session, image, settings):
        """Claim a job, then let its lease lapse without the worker reporting."""
        queue.enqueue(session, image.id)
        job = queue.claim(session, lease_seconds=600)
        job.lease_until = datetime.now(UTC) - timedelta(seconds=1)
        session.flush()
        tick(session, settings)
        return session.query(ScanJob).filter(ScanJob.image_id == image.id).one()

    def _runs(self, session, image):
        return session.query(ScanRun).filter(ScanRun.image_id == image.id).all()

    def test_a_dead_attempt_is_recorded_as_a_failed_run(self, session, image, settings):
        self._strand(session, image, settings)

        runs = self._runs(session, image)
        assert len(runs) == 1
        assert runs[0].status == RunStatus.FAILED
        assert "lease expired" in runs[0].error

    def test_the_image_reflects_that_its_scan_died(self, session, image, settings):
        self._strand(session, image, settings)

        session.refresh(image)
        assert image.last_scan_status == RunStatus.FAILED
        assert image.last_scan_at is not None

    def test_a_reap_with_attempts_left_does_not_advance_the_failure_streak(
        self, session, image, settings
    ):
        job = self._strand(session, image, settings)

        assert job.status == JobStatus.PENDING
        session.refresh(image)
        # The streak counts exhausted jobs, not attempts -- same rule as a worker
        # that lived long enough to report the failure itself.
        assert image.consecutive_failures == 0

    def test_a_reap_that_exhausts_the_job_does(self, session, image, settings):
        settings = Settings(max_attempts=1)
        job = self._strand(session, image, settings)

        assert job.status == JobStatus.FAILED
        session.refresh(image)
        assert image.consecutive_failures == 1

    def test_a_live_lease_is_not_disturbed(self, session, image, settings):
        queue.enqueue(session, image.id)
        queue.claim(session, lease_seconds=600)
        session.flush()

        tick(session, settings)

        assert self._runs(session, image) == []
        session.refresh(image)
        assert image.last_scan_status is None
