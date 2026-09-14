"""How the worker classifies what went wrong.

``run_once`` is a dispatch table: each exception a scan can raise routes to one of
three outcomes -- defer at no cost, burn one attempt, or burn the whole allowance --
and the routing is the system's entire failure policy. Nothing else enforces it.
The ordering of its ``except`` clauses is load-bearing in particular, because
``RateLimited`` and ``TrivyRateLimited`` both subclass an exception a later clause
catches: reorder them and a throttled registry silently starts retiring healthy
images as permanently failed, with every other test in the suite still green.

So these tests drive ``run_once`` against a real queue with ``_execute`` stubbed to
raise, and assert on the rows afterwards. The last class stubs the boundary one level
lower -- registry and Trivy -- to check that ``_execute`` itself wires the skip
invariant to ``record_skip`` rather than ``record_success``.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.config import Settings
from app.domain.models import JobStatus, RunStatus, ScanJob, ScanRun
from app.domain.severity import Severity
from app.jobs import queue
from app.registry.digest import ImageNotFound, RateLimited, RegistryError
from app.scanner import persist, trivy, worker
from app.scanner.parser import ParsedFinding, ParsedReport, TrivyReportError

pytestmark = pytest.mark.postgres

FIXTURES = Path(__file__).parent / "fixtures" / "trivy"


@pytest.fixture
def settings() -> Settings:
    return Settings()


def _queued(session, image) -> ScanJob:
    queue.enqueue(session, image.id)
    session.flush()
    return session.execute(
        ScanJob.__table__.select().where(ScanJob.image_id == image.id)
    ).one()


def _runs(session, image) -> list[ScanRun]:
    return list(
        session.query(ScanRun)
        .filter(ScanRun.image_id == image.id)
        .order_by(ScanRun.id)
        .all()
    )


def _job(session, image) -> ScanJob:
    return session.query(ScanJob).filter(ScanJob.image_id == image.id).one()


def _fails_with(monkeypatch, error: Exception) -> None:
    """Make the scan raise, leaving run_once's dispatch as the thing under test."""

    def _execute(session, job, settings):
        raise error

    monkeypatch.setattr(worker, "_execute", _execute)


class TestBackpressureIsNotFailure:
    """A registry declining to serve us must cost nothing.

    This is the half of the policy that the README's token-bucket section turns on:
    if throttling burned attempts, a slow afternoon at Docker Hub would walk every
    image in the fleet to permanently failed.
    """

    @pytest.mark.parametrize(
        "error",
        [
            RateLimited("docker hub is throttling us", retry_after=42),
            trivy.TrivyRateLimited("trivy exited 1: toomanyrequests"),
        ],
        ids=["registry-429", "trivy-stderr"],
    )
    def test_throttling_defers_without_burning_an_attempt(
        self, session, image, settings, monkeypatch, error
    ):
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, error)

        assert worker.run_once(session, settings) is True

        job = _job(session, image)
        assert job.status == JobStatus.PENDING
        assert job.attempts == 0
        assert job.scheduled_for > datetime.now(UTC)

    def test_the_registrys_own_retry_after_sets_the_delay(
        self, session, image, settings, monkeypatch
    ):
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, RateLimited("throttled", retry_after=900))

        worker.run_once(session, settings)

        due_in = (_job(session, image).scheduled_for - datetime.now(UTC)).total_seconds()
        assert 840 < due_in <= 900

    def test_a_registry_that_says_nothing_gets_the_fallback_wait(
        self, session, image, settings, monkeypatch
    ):
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, RateLimited("throttled", retry_after=None))

        worker.run_once(session, settings)

        due_in = (_job(session, image).scheduled_for - datetime.now(UTC)).total_seconds()
        assert due_in == pytest.approx(worker.DEFAULT_DEFER_SECONDS, abs=60)

    def test_a_deferred_job_records_no_scan_run(
        self, session, image, settings, monkeypatch
    ):
        # Nothing was attempted, so there is no attempt to record. A scan_run here
        # would show up on /api/images as a failed scan the image never had.
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, RateLimited("throttled"))

        worker.run_once(session, settings)

        assert _runs(session, image) == []
        assert image.last_scan_status is None

    def test_backpressure_leaves_the_image_failure_streak_alone(
        self, session, image, settings, monkeypatch
    ):
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, RateLimited("throttled"))

        worker.run_once(session, settings)

        session.refresh(image)
        assert image.consecutive_failures == 0


class TestFailureDispatch:
    def test_a_missing_reference_burns_the_whole_allowance_at_once(
        self, session, image, settings, monkeypatch
    ):
        # A tag that does not exist will not start existing on retry, so backing off
        # five times before admitting it is pure waste.
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, ImageNotFound("library/nope:1.0 not found"))

        worker.run_once(session, settings)

        job = _job(session, image)
        assert job.status == JobStatus.FAILED
        assert job.attempts == 1

    @pytest.mark.parametrize(
        "error",
        [
            RegistryError("registry request failed: timeout"),
            trivy.TrivyError("trivy exited 1: MANIFEST_UNKNOWN"),
            trivy.TrivyTimeout("trivy timed out after 900s"),
            TrivyReportError("Trivy output is not valid JSON"),
        ],
        ids=["registry", "trivy", "timeout", "unparseable-report"],
    )
    def test_a_transient_failure_is_retried_with_backoff(
        self, session, image, settings, monkeypatch, error
    ):
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, error)

        worker.run_once(session, settings)

        job = _job(session, image)
        assert job.status == JobStatus.PENDING
        assert job.attempts == 1
        assert job.scheduled_for > datetime.now(UTC)

    def test_an_unexpected_error_does_not_escape_the_loop(
        self, session, image, settings, monkeypatch
    ):
        # A worker that dies on an unforeseen exception stops scanning everything
        # else, so the catch-all must still park the job properly.
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, ZeroDivisionError("something nobody predicted"))

        assert worker.run_once(session, settings) is True
        assert _job(session, image).status == JobStatus.PENDING

    def test_every_failure_leaves_a_queryable_row_not_a_log_line(
        self, session, image, settings, monkeypatch
    ):
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, ImageNotFound("library/nope:1.0 not found"))

        worker.run_once(session, settings)

        runs = _runs(session, image)
        assert len(runs) == 1
        assert runs[0].status == RunStatus.FAILED
        assert "ImageNotFound" in runs[0].error

    def test_an_exhausted_job_advances_the_image_failure_streak(
        self, session, image, settings, monkeypatch
    ):
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, ImageNotFound("gone"))

        worker.run_once(session, settings)

        session.refresh(image)
        assert image.consecutive_failures == 1

    def test_a_retryable_failure_does_not(
        self, session, image, settings, monkeypatch
    ):
        # The streak counts exhausted jobs, not attempts: one transient blip must not
        # push a healthy image onto a multi-hour cadence.
        queue.enqueue(session, image.id)
        _fails_with(monkeypatch, RegistryError("timeout"))

        worker.run_once(session, settings)

        session.refresh(image)
        assert image.consecutive_failures == 0


class TestClaiming:
    def test_an_empty_queue_is_not_work(self, session, settings):
        assert worker.run_once(session, settings) is False

    def test_a_job_scheduled_in_the_future_is_not_yet_work(
        self, session, image, settings
    ):
        queue.enqueue(
            session, image.id, scheduled_for=datetime.now(UTC) + timedelta(hours=1)
        )
        session.flush()
        assert worker.run_once(session, settings) is False


class TestExecuteWiring:
    """``_execute`` one level down: registry and Trivy stubbed, persistence real."""

    DIGEST = "sha256:" + "a" * 64

    @pytest.fixture
    def stub_boundary(self, monkeypatch):
        """Pin the four inputs to the skip invariant; let the caller vary them."""
        state = {"digest": self.DIGEST, "version": "0.58.1", "db": "2026-09-14", "scans": 0}

        def run_scan(image_ref, settings):
            state["scans"] += 1
            return (FIXTURES / "nginx-1.19.json").read_text(encoding="utf-8")

        monkeypatch.setattr(worker, "resolve_digest", lambda ref, **kw: state["digest"])
        monkeypatch.setattr(
            trivy, "probe_versions", lambda s: (state["version"], state["db"])
        )
        monkeypatch.setattr(trivy, "run_scan", run_scan)
        return state

    def _previous_success(self, session, image, settings, state):
        """A completed run matching the stubbed boundary exactly."""
        now = datetime.now(UTC)
        run = persist.record_success(
            session,
            image,
            None,
            ParsedReport(
                digest=state["digest"],
                artifact_name=image.reference,
                findings=(
                    ParsedFinding(
                        cve_id="CVE-2021-0001",
                        package_name="libssl1.1",
                        package_version="1.1.1d",
                        package_type="debian",
                        severity=Severity.HIGH,
                        fixed_version=None,
                        title=None,
                        description=None,
                        published_at=None,
                        last_modified_at=None,
                    ),
                ),
            ),
            persist.RunMetadata(
                digest=state["digest"],
                trivy_version=state["version"],
                trivy_db_version=state["db"],
                scan_flags_hash=trivy.scan_flags_hash(settings),
                started_at=now,
                completed_at=now,
            ),
        )
        session.flush()
        return run

    def test_an_unchanged_image_is_skipped_without_invoking_trivy(
        self, session, image, settings, stub_boundary
    ):
        previous = self._previous_success(session, image, settings, stub_boundary)
        queue.enqueue(session, image.id)

        worker.run_once(session, settings)

        assert stub_boundary["scans"] == 0
        session.refresh(image)
        assert image.last_scan_status == RunStatus.SKIPPED
        # Invariant 2: the previous run's findings are still exactly right.
        assert image.current_scan_run_id == previous.id
        assert _job(session, image).status == JobStatus.DONE

    def test_a_moved_tag_forces_a_real_scan(
        self, session, image, settings, stub_boundary
    ):
        self._previous_success(session, image, settings, stub_boundary)
        stub_boundary["digest"] = "sha256:" + "b" * 64
        queue.enqueue(session, image.id)

        worker.run_once(session, settings)

        assert stub_boundary["scans"] == 1
        session.refresh(image)
        assert image.last_scan_status == RunStatus.SUCCESS

    def test_a_refreshed_vulnerability_database_forces_a_scan(
        self, session, image, settings, stub_boundary
    ):
        # The case an elapsed-time heuristic gets wrong in the dangerous direction:
        # identical bytes, scanned moments ago, newly known to be vulnerable.
        self._previous_success(session, image, settings, stub_boundary)
        stub_boundary["db"] = "2026-09-15"
        queue.enqueue(session, image.id)

        worker.run_once(session, settings)

        assert stub_boundary["scans"] == 1

    def test_a_first_scan_records_findings_and_the_counts_that_summarise_them(
        self, session, image, settings, stub_boundary
    ):
        queue.enqueue(session, image.id)

        worker.run_once(session, settings)

        session.refresh(image)
        assert image.last_scan_status == RunStatus.SUCCESS
        run = session.get(ScanRun, image.current_scan_run_id)
        assert run.digest is not None
        assert run.finding_count_critical is not None
        assert _job(session, image).status == JobStatus.DONE
