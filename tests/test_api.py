"""The five endpoints the brief specifies, plus the behaviour around their edges.

Driven over ASGI rather than a live server, but against a real PostgreSQL, because
every one of these endpoints is a non-trivial SQL query and the interesting part is
the ``last_seen_run_id == current_scan_run_id`` filter that decides what counts as a
live vulnerability.

Isolation differs from the rest of the suite: the API is async (asyncpg) while the
fixtures elsewhere are sync (psycopg), so the savepoint-rollback trick cannot span
both connections. Instead this seeds committed rows under uuid-suffixed image names
and deletes them afterwards -- which is what the uuid naming in ``conftest`` exists
for in the first place.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from app.api.main import app
from app.config import get_settings
from app.db.session import get_session
from app.domain.models import Cve, Image, RunStatus
from app.domain.severity import Severity
from app.scanner import persist
from app.scanner.parser import ParsedFinding, ParsedReport

pytestmark = pytest.mark.postgres


@dataclass
class Seeded:
    """Two scanned images that share a CVE at different severities, plus an unscanned one."""

    alpha: Image
    beta: Image
    slashed: Image
    unscanned: Image
    shared_cve: str
    alpha_only_cve: str
    stale_cve: str
    cve_ids: list[str] = field(default_factory=list)


def _finding(cve: str, severity: Severity, package: str, version: str, pkg_type: str):
    return ParsedFinding(
        cve_id=cve,
        package_name=package,
        package_version=version,
        package_type=pkg_type,
        severity=severity,
        fixed_version="9.9.9",
        title=f"title for {cve}",
        description=f"description for {cve}",
        published_at=datetime(2021, 8, 24, tzinfo=UTC),
        last_modified_at=datetime(2022, 4, 5, tzinfo=UTC),
    )


def _report(*findings, digest: str):
    return ParsedReport(digest=digest, artifact_name="seeded", findings=findings)


def _meta(digest: str) -> persist.RunMetadata:
    started = datetime.now(UTC)
    return persist.RunMetadata(
        digest=digest,
        trivy_version="0.58.1",
        trivy_db_version="2026-09-14T06:00:00Z",
        scan_flags_hash="abc123",
        started_at=started,
        completed_at=started + timedelta(seconds=3),
    )


@pytest.fixture
def seeded(engine) -> Seeded:
    suffix = uuid.uuid4().hex[:10]
    shared, alpha_only, stale = (f"CVE-9999-{uuid.uuid4().hex[:10]}" for _ in range(3))

    with Session(bind=engine, expire_on_commit=False) as session:
        alpha = Image(name=f"test-api-alpha-{suffix}", tag="1.0")
        beta = Image(name=f"test-api-beta-{suffix}", tag="2.0")
        slashed = Image(name=f"test-org-{suffix}/nested", tag="3.0")
        unscanned = Image(name=f"test-api-unscanned-{suffix}", tag="4.0")
        session.add_all([alpha, beta, slashed, unscanned])
        session.flush()

        # First run of alpha carries a CVE that the second run drops. It must survive
        # as history and must not appear in any response.
        persist.record_success(
            session,
            alpha,
            None,
            _report(
                _finding(stale, Severity.LOW, "oldpkg", "0.1", "debian"),
                digest="sha256:alpha-old",
            ),
            _meta("sha256:alpha-old"),
        )
        persist.record_success(
            session,
            alpha,
            None,
            _report(
                _finding(shared, Severity.CRITICAL, "openssl", "1.0", "debian"),
                _finding(alpha_only, Severity.MEDIUM, "zlib", "1.2", "debian"),
                digest="sha256:alpha",
            ),
            _meta("sha256:alpha"),
        )
        # The same CVE, rated lower by a different distro. The rollup must say
        # CRITICAL while beta's own finding still says HIGH.
        persist.record_success(
            session,
            beta,
            None,
            _report(
                _finding(shared, Severity.HIGH, "openssl", "1.1", "alpine"),
                digest="sha256:beta",
            ),
            _meta("sha256:beta"),
        )
        persist.record_success(
            session,
            slashed,
            None,
            _report(
                _finding(alpha_only, Severity.MEDIUM, "zlib", "1.2", "debian"),
                digest="sha256:slashed",
            ),
            _meta("sha256:slashed"),
        )
        session.commit()

        data = Seeded(
            alpha=alpha,
            beta=beta,
            slashed=slashed,
            unscanned=unscanned,
            shared_cve=shared,
            alpha_only_cve=alpha_only,
            stale_cve=stale,
            cve_ids=[shared, alpha_only, stale],
        )

    yield data

    with Session(bind=engine) as session:
        # scan_run and finding cascade from image; cve has no FK back, so it goes here.
        session.execute(
            delete(Image).where(
                Image.id.in_([alpha.id, beta.id, slashed.id, unscanned.id])
            )
        )
        session.execute(delete(Cve).where(Cve.id.in_(data.cve_ids)))
        session.commit()


@pytest.fixture
async def client(engine):
    """An ASGI client whose session points at the test database."""
    settings = get_settings()
    base, _, _ = settings.async_dsn.rpartition("/")
    async_engine = create_async_engine(f"{base}/{settings.postgres_db}_test")
    factory = async_sessionmaker(bind=async_engine, expire_on_commit=False)

    async def override():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_session] = override
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http
    app.dependency_overrides.clear()
    await async_engine.dispose()


def items_by_name(payload: dict) -> dict[str, dict]:
    return {i["name"]: i for i in payload["items"]}


class TestHealth:
    async def test_reports_ok_and_scanner_state(self, client, seeded):
        response = await client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["database"] == "ok"
        # Not just connectivity: an API answering while nothing has scanned in hours
        # is not healthy, so these have to be present.
        assert body["images_enabled"] >= 4
        assert body["last_successful_scan_at"] is not None


class TestListImages:
    async def test_summarises_severity_counts_over_current_findings_only(
        self, client, seeded
    ):
        payload = (await client.get("/api/images", params={"limit": 1000})).json()
        alpha = items_by_name(payload)[seeded.alpha.name]

        assert alpha["total_cves"] == 2
        assert alpha["severity_counts"]["CRITICAL"] == 1
        assert alpha["severity_counts"]["MEDIUM"] == 1
        # The dropped finding from alpha's first run must not be counted.
        assert alpha["severity_counts"]["LOW"] == 0

    async def test_counts_always_sum_to_the_total(self, client, seeded):
        payload = (await client.get("/api/images", params={"limit": 1000})).json()
        for image in payload["items"]:
            assert image["total_cves"] == sum(image["severity_counts"].values())

    async def test_reports_the_digest_of_the_current_run(self, client, seeded):
        payload = (await client.get("/api/images", params={"limit": 1000})).json()
        assert items_by_name(payload)[seeded.alpha.name]["digest"] == "sha256:alpha"

    async def test_an_unscanned_image_is_listed_rather_than_hidden(self, client, seeded):
        payload = (await client.get("/api/images", params={"limit": 1000})).json()
        unscanned = items_by_name(payload)[seeded.unscanned.name]
        assert unscanned["last_scan_status"] is None
        assert unscanned["total_cves"] == 0
        assert unscanned["digest"] is None

    async def test_a_healthy_image_reports_no_failure_streak(self, client, seeded):
        payload = (await client.get("/api/images", params={"limit": 1000})).json()
        assert items_by_name(payload)[seeded.alpha.name]["consecutive_failures"] == 0

    async def test_the_failure_streak_is_visible(self, client, seeded, engine):
        # A rotting reference should be findable from the API, not just cheap: this is
        # the field that says "a human needs to look at this image".
        from sqlalchemy.orm import Session as SyncSession

        with SyncSession(bind=engine) as setup:
            setup.execute(
                Image.__table__.update()
                .where(Image.__table__.c.id == seeded.unscanned.id)
                .values(consecutive_failures=4)
            )
            setup.commit()

        payload = (await client.get("/api/images", params={"limit": 1000})).json()
        assert items_by_name(payload)[seeded.unscanned.name]["consecutive_failures"] == 4

    async def test_effective_interval_includes_the_global_default(self, client, seeded):
        payload = (await client.get("/api/images", params={"limit": 1000})).json()
        assert items_by_name(payload)[seeded.alpha.name]["scan_interval_seconds"] == 900

    async def test_pagination_reports_the_unpaged_total(self, client, seeded):
        payload = (await client.get("/api/images", params={"limit": 1})).json()
        assert len(payload["items"]) == 1
        assert payload["pagination"]["total"] >= 4
        assert payload["pagination"]["limit"] == 1

    async def test_limit_is_clamped_to_the_configured_maximum(self, client, seeded):
        payload = (await client.get("/api/images", params={"limit": 99999})).json()
        assert payload["pagination"]["limit"] == get_settings().page_size_max


class TestImageCves:
    async def test_lists_current_findings_highest_severity_first(self, client, seeded):
        path = f"/api/images/{seeded.alpha.name}/{seeded.alpha.tag}/cves"
        payload = (await client.get(path, params={"limit": 1000})).json()

        assert [i["cve_id"] for i in payload["items"]] == [
            seeded.shared_cve,
            seeded.alpha_only_cve,
        ]
        assert payload["items"][0]["severity"] == "CRITICAL"

    async def test_a_finding_that_stopped_being_reported_is_absent(self, client, seeded):
        path = f"/api/images/{seeded.alpha.name}/{seeded.alpha.tag}/cves"
        payload = (await client.get(path, params={"limit": 1000})).json()
        assert seeded.stale_cve not in {i["cve_id"] for i in payload["items"]}

    async def test_carries_package_and_fix_details(self, client, seeded):
        path = f"/api/images/{seeded.alpha.name}/{seeded.alpha.tag}/cves"
        first = (await client.get(path)).json()["items"][0]
        assert first["package"] == {"name": "openssl", "version": "1.0", "type": "debian"}
        assert first["fixed_version"] == "9.9.9"
        assert first["title"] == f"title for {seeded.shared_cve}"

    @pytest.mark.parametrize(
        "severity,expected", [("CRITICAL", 1), ("MEDIUM", 1), ("HIGH", 0), ("LOW", 0)]
    )
    async def test_severity_filter_is_honoured(self, client, seeded, severity, expected):
        path = f"/api/images/{seeded.alpha.name}/{seeded.alpha.tag}/cves"
        payload = (await client.get(path, params={"severity": severity})).json()
        assert payload["pagination"]["total"] == expected
        assert all(i["severity"] == severity for i in payload["items"])

    async def test_severity_filter_is_case_insensitive(self, client, seeded):
        path = f"/api/images/{seeded.alpha.name}/{seeded.alpha.tag}/cves"
        payload = (await client.get(path, params={"severity": "critical"})).json()
        assert payload["pagination"]["total"] == 1

    async def test_an_image_name_containing_a_slash_resolves(self, client, seeded):
        # bitnami/redis and friends: the route uses {image_name:path} for this.
        path = f"/api/images/{seeded.slashed.name}/{seeded.slashed.tag}/cves"
        response = await client.get(path)
        assert response.status_code == 200
        assert response.json()["pagination"]["total"] == 1

    async def test_an_image_with_no_successful_scan_is_empty_not_an_error(
        self, client, seeded
    ):
        path = f"/api/images/{seeded.unscanned.name}/{seeded.unscanned.tag}/cves"
        response = await client.get(path)
        assert response.status_code == 200
        assert response.json()["items"] == []

    async def test_unknown_image_is_404(self, client, seeded):
        assert (await client.get("/api/images/nope/nope/cves")).status_code == 404

    async def test_invalid_severity_is_400(self, client, seeded):
        path = f"/api/images/{seeded.alpha.name}/{seeded.alpha.tag}/cves"
        assert (await client.get(path, params={"severity": "SEVERE"})).status_code == 400


class TestListCves:
    async def _find(self, client, cve_id: str) -> dict | None:
        payload = (await client.get("/api/cves", params={"limit": 1000})).json()
        return next((c for c in payload["items"] if c["cve_id"] == cve_id), None)

    async def test_rolls_severity_up_across_images(self, client, seeded):
        # CRITICAL in alpha, HIGH in beta -- the rollup is CRITICAL.
        assert (await self._find(client, seeded.shared_cve))["max_severity"] == "CRITICAL"

    async def test_counts_the_images_a_cve_affects(self, client, seeded):
        assert (await self._find(client, seeded.shared_cve))["affected_image_count"] == 2
        assert (await self._find(client, seeded.alpha_only_cve))["affected_image_count"] == 2

    async def test_a_cve_no_image_currently_reports_is_excluded(self, client, seeded):
        # The row still exists for history; it is simply not a live vulnerability.
        assert await self._find(client, seeded.stale_cve) is None

    async def test_each_cve_appears_once_however_many_images_carry_it(self, client, seeded):
        payload = (await client.get("/api/cves", params={"limit": 1000})).json()
        ids = [c["cve_id"] for c in payload["items"]]
        assert len(ids) == len(set(ids))

    async def test_severity_filter_matches_the_rollup(self, client, seeded):
        payload = (await client.get(
            "/api/cves", params={"severity": "CRITICAL", "limit": 1000}
        )).json()
        assert seeded.shared_cve in {c["cve_id"] for c in payload["items"]}
        assert all(c["max_severity"] == "CRITICAL" for c in payload["items"])

    async def test_the_filter_is_on_the_rollup_not_on_any_single_image(self, client, seeded):
        # Documented consequence: this CVE is genuinely HIGH in beta, but its rollup is
        # CRITICAL, so ?severity=HIGH does not return it. Asking "which CVEs are HIGH
        # in some image" is the per-image endpoint's job.
        payload = (await client.get(
            "/api/cves", params={"severity": "HIGH", "limit": 1000}
        )).json()
        assert seeded.shared_cve not in {c["cve_id"] for c in payload["items"]}

    async def test_invalid_severity_is_400(self, client, seeded):
        assert (await client.get("/api/cves", params={"severity": "SEVERE"})).status_code == 400


class TestCveImages:
    async def test_lists_every_affected_image_with_its_package(self, client, seeded):
        payload = (await client.get(f"/api/cves/{seeded.shared_cve}/images")).json()
        by_name = items_by_name(payload)

        assert {seeded.alpha.name, seeded.beta.name} <= set(by_name)
        assert by_name[seeded.alpha.name]["package"]["version"] == "1.0"
        assert by_name[seeded.beta.name]["package"]["type"] == "alpine"

    async def test_severity_is_reported_per_image_not_as_the_rollup(self, client, seeded):
        # The point of severity living on the finding: the same CVE, two ratings.
        payload = (await client.get(f"/api/cves/{seeded.shared_cve}/images")).json()
        by_name = items_by_name(payload)
        assert by_name[seeded.alpha.name]["severity"] == "CRITICAL"
        assert by_name[seeded.beta.name]["severity"] == "HIGH"

    async def test_reports_the_digest_the_finding_describes(self, client, seeded):
        payload = (await client.get(f"/api/cves/{seeded.shared_cve}/images")).json()
        assert items_by_name(payload)[seeded.alpha.name]["digest"] == "sha256:alpha"

    async def test_a_cve_only_in_history_lists_no_images(self, client, seeded):
        response = await client.get(f"/api/cves/{seeded.stale_cve}/images")
        assert response.status_code == 200
        assert response.json()["items"] == []

    async def test_unknown_cve_is_404(self, client, seeded):
        assert (await client.get("/api/cves/CVE-0000-0000/images")).status_code == 404


class TestConditionalRequests:
    async def test_collections_carry_validators(self, client, seeded):
        response = await client.get("/api/images")
        assert response.headers.get("ETag")
        assert response.headers.get("Last-Modified")

    async def test_matching_etag_returns_304_without_a_body(self, client, seeded):
        first = await client.get("/api/images")
        again = await client.get(
            "/api/images", headers={"If-None-Match": first.headers["ETag"]}
        )
        assert again.status_code == 304
        assert not again.content
        assert again.headers["ETag"] == first.headers["ETag"]

    async def test_a_stale_etag_still_returns_the_body(self, client, seeded):
        response = await client.get("/api/images", headers={"If-None-Match": 'W/"1"'})
        assert response.status_code == 200
        assert response.json()["items"]


class TestScanTrigger:
    async def test_queues_a_scan_for_a_known_image(self, client, seeded):
        path = f"/api/images/{seeded.alpha.name}/{seeded.alpha.tag}/scan"
        response = await client.post(path)
        assert response.status_code == 202
        assert response.json()["status"] == "queued"

    async def test_a_second_request_does_not_duplicate_the_job(self, client, seeded):
        path = f"/api/images/{seeded.beta.name}/{seeded.beta.tag}/scan"
        assert (await client.post(path)).json()["status"] == "queued"
        # One active job per image is a partial unique index, not application logic.
        assert (await client.post(path)).json()["status"] == "already_queued"

    async def test_urgency_promotes_the_waiting_job_instead_of_queueing_another(
        self, client, seeded
    ):
        path = f"/api/images/{seeded.slashed.name}/{seeded.slashed.tag}/scan"
        await client.post(path)
        promoted = (await client.post(path, params={"time_sensitive": "true"})).json()
        assert promoted["status"] == "promoted"
        assert promoted["time_sensitive"] is True

    async def test_unknown_image_is_404(self, client, seeded):
        assert (await client.post("/api/images/nope/nope/scan")).status_code == 404


class TestRunStatusVocabulary:
    async def test_last_scan_status_uses_the_domain_vocabulary(self, client, seeded):
        payload = (await client.get("/api/images", params={"limit": 1000})).json()
        statuses = {i["last_scan_status"] for i in payload["items"]} - {None}
        assert statuses <= {s.value for s in RunStatus}
