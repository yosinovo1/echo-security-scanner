"""Severity vocabulary.

Severity is a property of a *finding*, not of a CVE: Trivy reports vendor severity
per target, and Debian, Alpine and NVD routinely disagree about the same CVE. The
rank is denormalised onto the finding row so the CVE-level rollup is a single
``MAX()`` in SQL.
"""
from __future__ import annotations

import enum


class Severity(str, enum.Enum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


#: Ordering used for the CVE-level rollup. Higher wins.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

RANK_TO_SEVERITY: dict[int, Severity] = {v: k for k, v in SEVERITY_RANK.items()}

#: The four levels the brief's ?severity= filter accepts.
FILTERABLE = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def parse_severity(raw: str | None) -> Severity:
    """Map a Trivy severity string onto the enum, tolerating junk and absence."""
    if not raw:
        return Severity.UNKNOWN
    try:
        return Severity(raw.strip().upper())
    except ValueError:
        return Severity.UNKNOWN


def rank(severity: Severity) -> int:
    return SEVERITY_RANK[severity]


def max_severity(severities: list[Severity] | tuple[Severity, ...]) -> Severity:
    if not severities:
        return Severity.UNKNOWN
    return max(severities, key=rank)
