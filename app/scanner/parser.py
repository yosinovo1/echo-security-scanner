"""Trivy JSON -> domain objects.

Everything that can plausibly be wrong about a Trivy report is decided here rather
than in ``trivy.py``: severity variance across distros, a missing ``FixedVersion``,
a null ``Results``, a vulnerability listed twice under different targets, junk dates.
``trivy.py`` is deliberately a dozen lines of subprocess plumbing so that this module
carries the logic the tests can actually exercise.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from app.domain.severity import Severity, parse_severity, rank


class TrivyReportError(ValueError):
    """Raised when Trivy output cannot be interpreted at all."""


@dataclass(frozen=True, slots=True)
class ParsedFinding:
    cve_id: str
    package_name: str
    package_version: str
    package_type: str
    severity: Severity
    fixed_version: str | None
    title: str | None
    description: str | None
    published_at: datetime | None
    last_modified_at: datetime | None

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Matches the uq_finding_img_cve_pkg uniqueness grain."""
        return (self.cve_id, self.package_name, self.package_version, self.package_type)


@dataclass(frozen=True, slots=True)
class ParsedReport:
    digest: str | None
    artifact_name: str | None
    findings: tuple[ParsedFinding, ...]


def _parse_datetime(raw: object) -> datetime | None:
    """Trivy emits RFC3339, but also emits the zero time for "unknown"."""
    if not isinstance(raw, str) or not raw:
        return None
    text = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.year <= 1:  # 0001-01-01T00:00:00Z means "no date", not year 1.
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _extract_digest(metadata: dict) -> str | None:
    """Prefer the repo digest, which identifies the bytes in the registry.

    ``RepoDigests`` entries look like ``nginx@sha256:abc...``; ImageID is the local
    config digest and is only a fallback.
    """
    repo_digests = metadata.get("RepoDigests") or []
    if isinstance(repo_digests, list):
        for entry in repo_digests:
            if isinstance(entry, str) and "@" in entry:
                return entry.split("@", 1)[1]
    image_id = metadata.get("ImageID")
    if isinstance(image_id, str) and image_id:
        return image_id
    return None


def _clean(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def parse_report(raw: str | bytes) -> ParsedReport:
    """Parse one ``trivy image --format json`` document."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if not raw.strip():
        raise TrivyReportError("Trivy produced no output")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TrivyReportError(f"Trivy output is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise TrivyReportError("Trivy output is not a JSON object")

    metadata = document.get("Metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    # A clean image legitimately has Results absent or null -- that is zero findings,
    # not a failure.
    results = document.get("Results") or []
    if not isinstance(results, list):
        raise TrivyReportError("Trivy Results is not a list")

    # A CVE can appear under more than one target at the same package grain; keep the
    # highest severity rather than letting an arbitrary one win.
    deduped: dict[tuple[str, str, str, str], ParsedFinding] = {}

    for result in results:
        if not isinstance(result, dict):
            continue
        package_type = _clean(result.get("Type")) or "unknown"
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            cve_id = _clean(vulnerability.get("VulnerabilityID"))
            package_name = _clean(vulnerability.get("PkgName"))
            if not cve_id or not package_name:
                # Without both we cannot key the finding; skip rather than invent one.
                continue

            finding = ParsedFinding(
                cve_id=cve_id,
                package_name=package_name,
                package_version=_clean(vulnerability.get("InstalledVersion")) or "unknown",
                package_type=package_type,
                severity=parse_severity(vulnerability.get("Severity")),
                # Absent FixedVersion means "no fix published", which is meaningful.
                fixed_version=_clean(vulnerability.get("FixedVersion")),
                title=_clean(vulnerability.get("Title")),
                description=_clean(vulnerability.get("Description")),
                published_at=_parse_datetime(vulnerability.get("PublishedDate")),
                last_modified_at=_parse_datetime(vulnerability.get("LastModifiedDate")),
            )

            existing = deduped.get(finding.key)
            if existing is None or rank(finding.severity) > rank(existing.severity):
                deduped[finding.key] = finding

    return ParsedReport(
        digest=_extract_digest(metadata),
        artifact_name=_clean(document.get("ArtifactName")),
        findings=tuple(deduped.values()),
    )
