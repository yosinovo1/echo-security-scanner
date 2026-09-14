"""Queue behaviour, against a real PostgreSQL.

Skipped automatically when no database is reachable.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.domain.models import JobStatus, ScanJob
from app.jobs import queue

pytestmark = pytest.mark.postgres



def now() -> datetime:
    return datetime.now(UTC)


def jobs_for(session, image) -> list[ScanJob]:
    return list(
        session.execute(select(ScanJob).where(ScanJob.image_id == image.id)).scalars().all()
    )


class TestEnqueue:
    def test_enqueue_creates_a_pending_job(self, session, image):
        assert queue.enqueue(session, image.id) is True
        (job,) = jobs_for(session, image)
        assert job.status == JobStatus.PENDING
        assert job.priority == queue.PRIORITY_SCHEDULED

    def test_second_enqueue_is_refused_while_one_is_active(self, session, image):
        assert queue.enqueue(session, image.id) is True
        assert queue.enqueue(session, image.id) is False
        assert len(jobs_for(session, image)) == 1

    def test_running_job_also_blocks_a_second_enqueue(self, session, image):
        queue.enqueue(session, image.id)
        queue.claim(session, lease_seconds=600)
        assert queue.enqueue(session, image.id) is False

    def test_completed_job_frees_the_image_for_rescheduling(self, session, image):
        queue.enqueue(session, image.id)
        job = queue.claim(session, lease_seconds=600)
        queue.complete(session, job)
        session.flush()
        assert queue.enqueue(session, image.id) is True

    def test_permanently_failed_job_does_not_wedge_the_queue(self, session, image):
        queue.enqueue(session, image.id)
        job = queue.claim(session, lease_seconds=600)
        queue.fail(
            session, job, "boom", max_attempts=1, backoff_base_seconds=30, backoff_max_seconds=60
        )
        session.flush()
        assert job.status == JobStatus.FAILED
        assert queue.enqueue(session, image.id) is True


class TestClaim:
    def test_returns_none_when_the_queue_is_empty(self, session):
        assert queue.claim(session, lease_seconds=600) is None

    def test_sets_running_and_a_lease(self, session, image):
        queue.enqueue(session, image.id)
        job = queue.claim(session, lease_seconds=600)
        assert job.status == JobStatus.RUNNING
        assert job.lease_until is not None
        assert job.lease_until > now()

    def test_does_not_claim_a_job_scheduled_in_the_future(self, session, image):
        queue.enqueue(session, image.id, scheduled_for=now() + timedelta(minutes=5))
        assert queue.claim(session, lease_seconds=600) is None

    def test_time_sensitive_job_overtakes_the_scheduled_baseline(
        self, session, image, other_image
    ):
        queue.enqueue(session, image.id, scheduled_for=now() - timedelta(minutes=10))
        queue.enqueue(session, other_image.id, priority=queue.PRIORITY_TIME_SENSITIVE)
        session.flush()

        claimed = queue.claim(session, lease_seconds=600)
        # Despite being queued later, the urgent job goes first.
        assert claimed.image_id == other_image.id

    def test_older_job_wins_within_the_same_priority(self, session, image, other_image):
        queue.enqueue(session, image.id, scheduled_for=now() - timedelta(minutes=10))
        queue.enqueue(session, other_image.id, scheduled_for=now() - timedelta(minutes=1))
        session.flush()
        assert queue.claim(session, lease_seconds=600).image_id == image.id


class TestPromote:
    def test_pending_job_is_raised_to_the_urgent_lane(self, session, image):
        queue.enqueue(session, image.id, scheduled_for=now() + timedelta(hours=1))
        assert queue.promote(session, image.id) is True
        (job,) = jobs_for(session, image)
        assert job.priority == queue.PRIORITY_TIME_SENSITIVE
        # Promotion also pulls the job forward, so it is claimable now.
        assert queue.claim(session, lease_seconds=600) is not None

    def test_promoting_an_already_urgent_job_is_a_no_op(self, session, image):
        queue.enqueue(session, image.id, priority=queue.PRIORITY_TIME_SENSITIVE)
        assert queue.promote(session, image.id) is False

    def test_promoting_with_nothing_queued_reports_false(self, session, image):
        assert queue.promote(session, image.id) is False


class TestFailureHandling:
    def test_first_failure_retries_with_backoff(self, session, image):
        queue.enqueue(session, image.id)
        job = queue.claim(session, lease_seconds=600)
        before = now()
        queue.fail(
            session, job, "trivy exploded",
            max_attempts=3, backoff_base_seconds=30, backoff_max_seconds=3600,
        )
        assert job.status == JobStatus.PENDING
        assert job.attempts == 1
        assert job.scheduled_for >= before + timedelta(seconds=29)
        assert "trivy exploded" in job.last_error

    def test_backoff_grows_and_is_capped(self, session, image):
        queue.enqueue(session, image.id)
        job = queue.claim(session, lease_seconds=600)
        delays = []
        for _ in range(4):
            start = now()
            queue.fail(
                session, job, "again",
                max_attempts=99, backoff_base_seconds=30, backoff_max_seconds=120,
            )
            delays.append((job.scheduled_for - start).total_seconds())
        assert delays[0] < delays[1] < delays[2]
        assert delays[3] <= 121  # capped

    def test_exhausting_attempts_marks_the_job_failed(self, session, image):
        queue.enqueue(session, image.id)
        job = queue.claim(session, lease_seconds=600)
        for _ in range(3):
            queue.fail(
                session, job, "nope",
                max_attempts=3, backoff_base_seconds=1, backoff_max_seconds=10,
            )
        assert job.status == JobStatus.FAILED
        assert job.attempts == 3

    def test_defer_is_backpressure_not_failure(self, session, image):
        queue.enqueue(session, image.id)
        job = queue.claim(session, lease_seconds=600)
        queue.defer(session, job, 300, "registry budget exhausted")
        assert job.status == JobStatus.PENDING
        # The decisive part: a throttled job must not burn its retry allowance.
        assert job.attempts == 0
        assert job.scheduled_for > now() + timedelta(seconds=290)


class TestLeaseReaping:
    @staticmethod
    def _strand(session, image, *, max_attempts=5):
        """Claim a job and let its worker die without reporting."""
        job = queue.claim(session, lease_seconds=600)
        job.lease_until = now() - timedelta(seconds=1)
        session.flush()
        return job, queue.reap_expired_leases(session, max_attempts=max_attempts)

    def test_expired_lease_returns_the_job_to_the_queue(self, session, image):
        queue.enqueue(session, image.id)
        job, reaped = self._strand(session, image)

        assert len(reaped) == 1
        session.refresh(job)
        assert job.status == JobStatus.PENDING
        assert job.attempts == 1
        assert queue.claim(session, lease_seconds=600) is not None

    def test_live_lease_is_left_alone(self, session, image):
        queue.enqueue(session, image.id)
        queue.claim(session, lease_seconds=600)
        assert queue.reap_expired_leases(session, max_attempts=5) == []

    def test_a_reaped_attempt_counts_against_the_allowance(self, session, image):
        """The bug this closes: a scan that kills its worker never reaches ``fail``.

        Without this the job is re-claimed forever, taking down one more worker each
        time, while the image's failure streak stays at zero because no *job* ever
        exhausts -- so the per-image backoff never engages either.
        """
        queue.enqueue(session, image.id)
        for attempt in range(1, 3):
            job, reaped = self._strand(session, image, max_attempts=3)
            assert reaped[0].exhausted is False
            session.refresh(job)
            assert (job.status, job.attempts) == (JobStatus.PENDING, attempt)

        job, reaped = self._strand(session, image, max_attempts=3)
        assert reaped[0].exhausted is True
        session.refresh(job)
        assert job.status == JobStatus.FAILED
        assert queue.claim(session, lease_seconds=600) is None

    def test_an_exhausted_reap_names_the_image_so_the_streak_can_advance(
        self, session, image
    ):
        queue.enqueue(session, image.id)
        _, reaped = self._strand(session, image, max_attempts=1)
        assert reaped[0].image_id == image.id
        assert reaped[0].exhausted is True

    def test_a_permanently_failed_reap_frees_the_image_for_rescheduling(
        self, session, image
    ):
        queue.enqueue(session, image.id)
        self._strand(session, image, max_attempts=1)
        # The partial unique index is released, so the image is not wedged forever.
        assert queue.enqueue(session, image.id) is True
