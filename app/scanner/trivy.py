"""Subprocess plumbing for Trivy.

Kept deliberately tiny. The test suite mocks the subprocess boundary, so anything
that can be *wrong* about a scan belongs in ``parser.py`` below this line, not here.
Everything in this module is argv construction, process invocation, and exit codes.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess

from app.config import Settings


class TrivyError(RuntimeError):
    """Trivy could not be run, or exited non-zero."""


class TrivyTimeout(TrivyError):
    pass


def scan_flags(settings: Settings) -> list[str]:
    """Flags that affect the *result* of a scan.

    These feed ``scan_flags_hash`` and therefore the skip invariant, so changing any
    of them correctly invalidates every previous result.
    """
    flags = [
        "--format",
        "json",
        "--quiet",
        "--scanners",
        "vuln",
        "--image-src",
        "remote",
    ]
    if settings.trivy_server_url:
        # Client mode: the server owns the database, so this process never opens it.
        flags += ["--server", settings.trivy_server_url]
    else:
        # Standalone: the shared volume is already populated, so never re-download.
        flags += ["--skip-db-update"]
    return flags


def scan_flags_hash(settings: Settings) -> str:
    """Part of the skip invariant: changing the flags invalidates previous results."""
    payload = json.dumps(scan_flags(settings), sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def build_argv(image_ref: str, settings: Settings) -> list[str]:
    return [
        settings.trivy_bin,
        "image",
        "--cache-dir",
        settings.trivy_cache_dir,
        *scan_flags(settings),
        image_ref,
    ]


def _run(argv: list[str], timeout: int) -> str:
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise TrivyError(f"trivy binary not found: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise TrivyTimeout(f"trivy timed out after {timeout}s") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[:2000]
        raise TrivyError(f"trivy exited {completed.returncode}: {detail}")
    return completed.stdout


def run_scan(image_ref: str, settings: Settings) -> str:
    return _run(build_argv(image_ref, settings), settings.trivy_timeout_seconds)


def db_version(settings: Settings) -> str:
    """Read the vulnerability database version from the shared cache metadata.

    Read straight off ``db/metadata.json`` rather than out of ``trivy --version``,
    for two reasons. In client mode this process has no database of its own to
    report. And in standalone mode ``trivy --version`` only sees a database if it is
    handed the right ``--cache-dir``; get that wrong and this silently returns a
    constant, which defeats the skip invariant -- a refreshed database would stop
    forcing a rescan.

    Reading the metadata file never opens the bbolt database itself, so it does not
    contend with a scan in progress. It lives under ``trivy_db_dir`` (the server's
    cache, mounted read-only) rather than ``trivy_cache_dir`` (this worker's own
    writable scratch cache).
    """
    path = pathlib.Path(settings.trivy_db_dir) / "db" / "metadata.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "unknown"
    # UpdatedAt identifies the database contents far better than its schema number.
    return str(payload.get("UpdatedAt") or payload.get("Version") or "unknown")


def probe_versions(settings: Settings) -> tuple[str, str]:
    """Return ``(trivy_version, vulnerability_db_version)``.

    Both feed the skip invariant: a new scanner or a new vulnerability database can
    change the answer for unchanged image bytes.
    """
    raw = _run([settings.trivy_bin, "--version", "--format", "json"], timeout=60)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TrivyError(f"could not parse trivy --version output: {exc}") from exc

    return str(payload.get("Version") or "unknown"), db_version(settings)
