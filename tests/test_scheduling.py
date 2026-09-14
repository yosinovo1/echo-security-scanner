"""Pure-logic tests: reference parsing, jitter, and the skip invariant.

These need no database and no network, so they run everywhere.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.domain.models import Image, RunStatus, ScanRun
from app.registry.digest import DOCKER_HUB_HOST, parse_reference
from app.scanner.worker import _is_unchanged
from app.scheduler.jitter import jitter_offset
from app.scheduler.scheduler import next_due_at


class TestReferenceParsing:
    def test_single_component_name_lives_under_library(self):
        ref = parse_reference("nginx", "1.19")
        assert ref.host == DOCKER_HUB_HOST
        assert ref.repository == "library/nginx"
        assert ref.tag == "1.19"

    def test_two_component_docker_hub_name_is_left_alone(self):
        ref = parse_reference("bitnami/redis", "6.0")
        assert ref.host == DOCKER_HUB_HOST
        assert ref.repository == "bitnami/redis"

    @pytest.mark.parametrize(
        "name,host,repository",
        [
            ("ghcr.io/acme/api", "ghcr.io", "acme/api"),
            ("registry.example.com/team/app", "registry.example.com", "team/app"),
            ("localhost/dev", "localhost", "dev"),
            ("localhost:5000/dev", "localhost:5000", "dev"),
        ],
    )
    def test_leading_component_is_a_host_only_when_it_looks_like_one(
        self, name, host, repository
    ):
        ref = parse_reference(name, "latest")
        assert (ref.host, ref.repository) == (host, repository)

    def test_budget_is_keyed_by_host_since_that_is_what_rate_limits_us(self):
        assert parse_reference("nginx", "1.19").budget_key == DOCKER_HUB_HOST
        assert parse_reference("ghcr.io/a/b", "1").budget_key == "ghcr.io"


class TestJitter:
    def test_offset_is_inside_the_interval(self):
        assert all(0 <= jitter_offset(i, 900) < 900 for i in range(1, 500))

    def test_offset_is_stable_across_calls(self):
        # The whole point over random jitter: restarts must not re-converge the herd.
        assert jitter_offset(42, 900) == jitter_offset(42, 900)

    def test_different_images_get_different_offsets(self):
        offsets = {jitter_offset(i, 900) for i in range(1, 200)}
        assert len(offsets) > 150  # well spread, allowing for hash collisions

    def test_zero_interval_is_handled(self):
        assert jitter_offset(1, 0) == 0


class TestNextDue:
    def _image(self, **kwargs) -> Image:
        image = Image(name="nginx", tag="1.19")
        image.id = kwargs.pop("id", 1)
        image.created_at = kwargs.pop("created_at", datetime(2026, 1, 1, tzinfo=UTC))
        image.last_scan_at = kwargs.pop("last_scan_at", None)
        image.scan_interval_seconds = kwargs.pop("scan_interval_seconds", None)
        return image

    def test_never_scanned_image_is_spread_over_the_initial_window_not_the_interval(self):
        # The whole point: a cold start must not leave the system idle for a full
        # interval before anything is scanned.
        image = self._image()
        expected = image.created_at + timedelta(seconds=jitter_offset(image.id, 120))
        assert next_due_at(image, 900, 120) == expected
        assert next_due_at(image, 900, 120) < image.created_at + timedelta(seconds=120)

    def test_initial_window_never_exceeds_the_interval(self):
        image = self._image(scan_interval_seconds=30)
        assert next_due_at(image, 900, 120) < image.created_at + timedelta(seconds=30)

    def test_scanned_image_is_due_one_interval_after_the_last_scan(self):
        last = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        image = self._image(last_scan_at=last)
        assert next_due_at(image, 900, 120) == last + timedelta(seconds=900)

    def test_per_image_interval_overrides_the_global_default(self):
        last = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        image = self._image(last_scan_at=last, scan_interval_seconds=60)
        assert next_due_at(image, 900, 120) == last + timedelta(seconds=60)


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
