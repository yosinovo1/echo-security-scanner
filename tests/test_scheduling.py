"""Pure-logic tests: due-time arithmetic, the skip invariant, and lease configuration.

These need no database and no network, so they run everywhere. Registry reference
parsing lives in ``test_registry.py`` alongside the rest of the registry client.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.domain.models import Image, RunStatus, ScanRun
from app.scanner.worker import _is_unchanged
from app.scheduler.scheduler import next_due_at


class TestNextDue:
    def _image(self, **kwargs) -> Image:
        image = Image(name="nginx", tag="1.19")
        image.id = kwargs.pop("id", 1)
        image.created_at = kwargs.pop("created_at", datetime(2026, 1, 1, tzinfo=UTC))
        image.last_scan_at = kwargs.pop("last_scan_at", None)
        image.scan_interval_seconds = kwargs.pop("scan_interval_seconds", None)
        return image

    def test_never_scanned_image_is_due_immediately(self):
        # No cold-start jitter: the queue bounds concurrency, so delaying the enqueue
        # would only delay the first results. A newly added image scans on the next
        # tick rather than after a spread window.
        image = self._image()
        assert next_due_at(image, 900) == image.created_at

    def test_scanned_image_is_due_one_interval_after_the_last_scan(self):
        last = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        image = self._image(last_scan_at=last)
        assert next_due_at(image, 900) == last + timedelta(seconds=900)

    def test_per_image_interval_overrides_the_global_default(self):
        last = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        image = self._image(last_scan_at=last, scan_interval_seconds=60)
        assert next_due_at(image, 900) == last + timedelta(seconds=60)


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
