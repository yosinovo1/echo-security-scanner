"""Parser tests.

The subprocess boundary is mocked (see the plan's accepted trade-offs), so this file
carries the weight: every decision Trivy output can force is exercised here.
"""
from __future__ import annotations

from datetime import UTC
from pathlib import Path

import pytest

from app.domain.severity import Severity
from app.scanner.parser import (
    ParsedFinding,
    TrivyReportError,
    is_rate_limit_error,
    parse_report,
)

FIXTURES = Path(__file__).parent / "fixtures" / "trivy"


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def by_cve(findings: tuple[ParsedFinding, ...], cve_id: str) -> list[ParsedFinding]:
    return [f for f in findings if f.cve_id == cve_id]


class TestDigestExtraction:
    def test_prefers_repo_digest_over_image_id(self):
        report = parse_report(load("nginx-1.19.json"))
        assert report.digest == (
            "sha256:df13abe416e37eb3db4722840dd479b00ba193ac6606e7902331dcea50f4f1f2"
        )

    def test_falls_back_to_image_id_when_no_repo_digest(self):
        # ubuntu fixture has RepoTags but no RepoDigests.
        report = parse_report(load("severity-variance.json"))
        assert report.digest == (
            "sha256:1318b700e415001198d1bf66d260b07f67ca8a552b61b0da02b3832c778f221b"
        )

    def test_missing_metadata_yields_no_digest(self):
        report = parse_report('{"SchemaVersion": 2, "Results": []}')
        assert report.digest is None


class TestCleanImage:
    def test_null_results_is_zero_findings_not_an_error(self):
        report = parse_report(load("alpine-3.12-clean.json"))
        assert report.findings == ()
        assert report.artifact_name == "alpine:3.12"

    def test_absent_results_key(self):
        assert parse_report('{"SchemaVersion": 2}').findings == ()


class TestFindingFields:
    @pytest.fixture(scope="class")
    def findings(self):
        return parse_report(load("nginx-1.19.json")).findings

    def test_extracts_the_five_required_fields(self, findings):
        (finding,) = by_cve(findings, "CVE-2021-3711")
        assert finding.package_name == "libssl1.1"
        assert finding.package_version == "1.1.1d-0+deb10u5"
        assert finding.fixed_version == "1.1.1d-0+deb10u7"
        assert finding.severity is Severity.CRITICAL

    def test_absent_fixed_version_means_no_fix_published(self, findings):
        (finding,) = by_cve(findings, "CVE-2021-33574")
        assert finding.fixed_version is None

    def test_empty_string_fixed_version_normalises_to_none(self, findings):
        (finding,) = by_cve(findings, "CVE-2019-9923")
        assert finding.fixed_version is None

    def test_package_type_comes_from_the_enclosing_result(self, findings):
        assert {f.package_type for f in findings} == {"debian"}

    def test_unparseable_severity_falls_back_to_unknown(self, findings):
        (finding,) = by_cve(findings, "CVE-2021-UNKNOWN-SEV")
        assert finding.severity is Severity.UNKNOWN

    def test_null_vulnerabilities_list_is_skipped(self, findings):
        # The node-pkg result has "Vulnerabilities": null.
        assert len(findings) == 4


class TestDates:
    @pytest.fixture(scope="class")
    def findings(self):
        return parse_report(load("nginx-1.19.json")).findings

    def test_parses_rfc3339_as_utc(self, findings):
        (finding,) = by_cve(findings, "CVE-2021-3711")
        assert finding.published_at is not None
        assert finding.published_at.year == 2021
        assert finding.published_at.tzinfo is not None
        assert finding.published_at.utcoffset() == UTC.utcoffset(None)

    def test_zero_time_means_unknown_not_year_one(self, findings):
        (finding,) = by_cve(findings, "CVE-2019-9923")
        assert finding.published_at is None
        assert finding.last_modified_at is None

    def test_absent_dates(self, findings):
        (finding,) = by_cve(findings, "CVE-2021-UNKNOWN-SEV")
        assert finding.published_at is None


class TestDeduplication:
    """Severity is per-finding, so a duplicate at the same grain must keep the max."""

    @pytest.fixture(scope="class")
    def findings(self):
        return parse_report(load("severity-variance.json")).findings

    def test_same_cve_and_package_collapses_to_highest_severity(self, findings):
        debian = [
            f for f in by_cve(findings, "CVE-2022-0001") if f.package_type == "ubuntu"
        ]
        assert len(debian) == 1
        assert debian[0].severity is Severity.HIGH

    def test_different_package_type_is_a_distinct_finding(self, findings):
        types = {f.package_type for f in by_cve(findings, "CVE-2022-0001")}
        assert types == {"ubuntu", "python-pkg"}

    def test_rows_without_a_cve_id_or_package_name_are_dropped(self, findings):
        assert by_cve(findings, "CVE-2022-0002") == []
        assert all(f.package_name != "no-cve-id" for f in findings)

    def test_non_object_vulnerability_entries_are_ignored(self, findings):
        assert len(findings) == 2


class TestMalformedOutput:
    def test_empty_output_raises(self):
        with pytest.raises(TrivyReportError, match="no output"):
            parse_report("   ")

    def test_invalid_json_raises(self):
        with pytest.raises(TrivyReportError, match="not valid JSON"):
            parse_report("{not json")

    def test_json_array_at_top_level_raises(self):
        with pytest.raises(TrivyReportError, match="not a JSON object"):
            parse_report("[]")

    def test_results_of_wrong_type_raises(self):
        with pytest.raises(TrivyReportError, match="Results is not a list"):
            parse_report('{"Results": {"oops": true}}')

    def test_accepts_bytes(self):
        assert parse_report(b'{"Results": []}').findings == ()


class TestRateLimitClassification:
    """Telling throttling apart from failure, from stderr prose.

    The two outcomes are opposites -- defer without cost, or spend a retry -- and
    Trivy exits 1 for both, so this predicate is the only thing separating them.
    """

    @pytest.mark.parametrize(
        "stderr",
        [
            "toomanyrequests: You have reached your pull rate limit.",
            "GET https://registry-1.docker.io/v2/: TOOMANYREQUESTS",
            "unexpected status code 429 Too Many Requests",
            "Error: rate limit exceeded for anonymous pulls",
        ],
    )
    def test_registry_throttling_is_recognised(self, stderr):
        assert is_rate_limit_error(stderr) is True

    @pytest.mark.parametrize(
        "stderr",
        [
            "MANIFEST_UNKNOWN: manifest unknown",
            "failed to resolve target image: unauthorized",
            "context deadline exceeded",
            "",
            None,
        ],
    )
    def test_ordinary_failures_are_left_alone(self, stderr):
        assert is_rate_limit_error(stderr) is False

    def test_a_digest_containing_429_is_not_throttling(self):
        # The false positive that matters: a bare "429" substring match would defer
        # this forever without ever counting an attempt.
        assert is_rate_limit_error(
            "failed to get manifest sha256:429f1c0e429b2a: MANIFEST_UNKNOWN"
        ) is False
