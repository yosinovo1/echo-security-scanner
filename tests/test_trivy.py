"""The Trivy subprocess boundary, only where a mistake would be silent.

``trivy.py`` is deliberately thin and mostly untested -- argv construction and process
invocation fail loudly. Exit-code *classification* is the exception: throttling and
failure both exit 1, and confusing them is silent in both directions (a retry burnt on
backpressure, or an image deferred forever on a real error). So that one decision is
pinned here, with the subprocess mocked.
"""
from __future__ import annotations

import subprocess

import pytest

from app.config import Settings
from app.scanner import trivy


@pytest.fixture
def settings() -> Settings:
    return Settings()


def _completed(returncode: int, stderr: str = "", stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestExitCodeClassification:
    def test_throttling_raises_the_backpressure_error(self, monkeypatch, settings):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **k: _completed(1, "toomanyrequests: You have reached your pull rate limit"),
        )
        with pytest.raises(trivy.TrivyRateLimited):
            trivy.run_scan("nginx:1.19", settings)

    def test_an_ordinary_failure_stays_an_ordinary_failure(self, monkeypatch, settings):
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: _completed(1, "MANIFEST_UNKNOWN: manifest unknown")
        )
        with pytest.raises(trivy.TrivyError) as excinfo:
            trivy.run_scan("nginx:1.19", settings)
        # The distinction the worker dispatches on: this one must burn a retry.
        assert not isinstance(excinfo.value, trivy.TrivyRateLimited)

    def test_backpressure_is_still_a_trivy_error(self):
        # Guarantees an ordering mistake in the worker's except clauses degrades to
        # "retried" rather than "escaped the loop".
        assert issubclass(trivy.TrivyRateLimited, trivy.TrivyError)

    def test_success_returns_stdout(self, monkeypatch, settings):
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(0, stdout='{"x":1}'))
        assert trivy.run_scan("nginx:1.19", settings) == '{"x":1}'

    def test_a_missing_binary_is_a_trivy_error_not_a_crash(self, monkeypatch, settings):
        def boom(*a, **k):
            raise FileNotFoundError

        monkeypatch.setattr(subprocess, "run", boom)
        with pytest.raises(trivy.TrivyError, match="not found"):
            trivy.run_scan("nginx:1.19", settings)

    def test_a_timeout_is_distinguishable(self, monkeypatch, settings):
        def boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd="trivy", timeout=1)

        monkeypatch.setattr(subprocess, "run", boom)
        with pytest.raises(trivy.TrivyTimeout):
            trivy.run_scan("nginx:1.19", settings)
