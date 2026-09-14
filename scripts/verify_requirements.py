#!/usr/bin/env python
"""End-to-end verification against the original assignment brief.

Every check below names the requirement from ``docs/ASSIGNMENT-REQUIREMENTS.md`` that
it proves. This is the script to run before claiming the assignment is done, and the
one to re-run when explaining the submission.

    python scripts/verify_requirements.py                 # HTTP checks only
    python scripts/verify_requirements.py --with-db       # adds SQL + failure-path checks
    python scripts/verify_requirements.py --wait 900      # wait for first scans to land

Exit code is 0 only if every check passed.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass, field

import httpx

BRIEF_IMAGES = [
    ("nginx", "1.19"),
    ("postgres", "12"),
    ("redis", "6.0"),
    ("node", "14-alpine"),
    ("python", "3.8-slim"),
    ("alpine", "3.12"),
    ("ubuntu", "20.04"),
    ("mysql", "8.0"),
    ("mongo", "4.4"),
    ("httpd", "2.4"),
]

BOGUS_IMAGE = ("nginx", "definitely-not-a-real-tag")

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


@dataclass
class Report:
    results: list[tuple[str, str, bool, str]] = field(default_factory=list)

    def check(self, req: str, name: str, passed: bool, detail: str = "") -> bool:
        self.results.append((req, name, passed, detail))
        mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
        print(f"  [{mark}] {req:<6} {name}")
        if detail:
            print(f"         {DIM}{detail}{RESET}")
        return passed

    def summary(self) -> int:
        failed = [r for r in self.results if not r[2]]
        print(f"\n{'=' * 72}")
        print(f"{len(self.results) - len(failed)}/{len(self.results)} checks passed")
        if failed:
            print(f"\n{RED}Failed:{RESET}")
            for req, name, _, detail in failed:
                print(f"  {req:<6} {name}" + (f"  -- {detail}" if detail else ""))
        return 1 if failed else 0


def psql(sql: str) -> str:
    """Run SQL through the compose Postgres service."""
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "postgres",
         "psql", "-U", "scanner", "-d", "scanner", "-tAc", sql],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()}")
    return result.stdout.strip()


def wait_for_scans(client: httpx.Client, timeout: int) -> bool:
    """Block until every enabled image has a successful scan, or give up."""
    deadline = time.time() + timeout
    last = -1
    while time.time() < deadline:
        try:
            items = client.get("/api/images", params={"limit": 1000}).json()["items"]
        except Exception:
            time.sleep(5)
            continue
        brief = [i for i in items if (i["name"], i["tag"]) in set(BRIEF_IMAGES)]
        done = sum(1 for i in brief if i["last_scan_status"] in ("success", "skipped"))
        items = brief
        if done != last:
            remaining = int(deadline - time.time())
            print(
                f"  {DIM}{done}/{len(items)} images scanned "
                f"({remaining}s budget left){RESET}"
            )
            last = done
        if items and done == len(items):
            return True
        time.sleep(10)
    return False


# --------------------------------------------------------------------------
# Task 1 -- Image Scanner Service
# --------------------------------------------------------------------------
def check_scanner(client: httpx.Client, report: Report, use_db: bool) -> None:
    print(f"\n{YELLOW}Task 1 - Image Scanner Service{RESET}")

    images = client.get("/api/images", params={"limit": 1000}).json()["items"]
    registered = {(i["name"], i["tag"]) for i in images}

    missing = [f"{n}:{t}" for n, t in BRIEF_IMAGES if (n, t) not in registered]
    report.check("1.1", "all 10 brief images are registered", not missing,
                 f"missing: {missing}" if missing else f"{len(BRIEF_IMAGES)} images present")

    # Only the brief's images count: a --with-db run leaves a deliberately
    # unresolvable image behind, and it must not dilute the coverage number.
    brief = [i for i in images if (i["name"], i["tag"]) in set(BRIEF_IMAGES)]
    scanned = [i for i in brief if i["last_scan_status"] in ("success", "skipped")]
    unscanned = [f"{i['name']}:{i['tag']}" for i in brief if i not in scanned]
    report.check("1.2", "every brief image has been scanned", not unscanned,
                 f"{len(scanned)}/{len(BRIEF_IMAGES)} scanned"
                 + (f"; still waiting on {unscanned}" if unscanned else ""))

    intervals = {i["scan_interval_seconds"] for i in brief}
    report.check("1.3", "scan cadence is 15 minutes", intervals <= {900},
                 f"configured intervals (seconds): {sorted(intervals)}")

    # CVE fields the brief names explicitly: id, severity, package, installed
    # version, fixed version.
    sample = max(scanned, key=lambda i: i["total_cves"], default=None)
    if sample is not None and sample["total_cves"] == 0:
        sample = None
    if sample is None:
        report.check("1.4", "CVE fields extracted", False, "no image has findings yet")
    else:
        findings = client.get(
            f"/api/images/{sample['name']}/{sample['tag']}/cves", params={"limit": 200}
        ).json()["items"]
        required = {"cve_id", "severity", "package", "fixed_version"}
        complete = all(
            required <= set(f) and f["package"].get("name") and f["package"].get("version")
            for f in findings
        )
        report.check("1.4", "CVE id/severity/package/version extracted", complete,
                     f"{len(findings)} findings on {sample['name']}:{sample['tag']}")

        with_fix = [f for f in findings if f["fixed_version"]]
        report.check("1.5", "fixed_version is captured where one exists", bool(with_fix),
                     f"{len(with_fix)}/{len(findings)} findings carry a fix version")

    if not use_db:
        return

    # The brief asks for graceful failure handling. Prove it rather than assert it:
    # register an image that cannot resolve and confirm the failure is recorded and
    # the queue keeps moving.
    print(f"  {DIM}seeding an unresolvable image to exercise the failure path...{RESET}")
    name, tag = BOGUS_IMAGE
    psql(
        f"INSERT INTO image (name, tag) VALUES ('{name}', '{tag}') "
        "ON CONFLICT ON CONSTRAINT uq_image_name_tag DO NOTHING"
    )
    client.post(f"/api/images/{name}/{tag}/scan", params={"time_sensitive": "true"})

    deadline = time.time() + 180
    failed_row = ""
    while time.time() < deadline:
        failed_row = psql(
            "SELECT r.status, coalesce(left(r.error, 90), '') FROM scan_run r "
            f"JOIN image i ON i.id = r.image_id WHERE i.tag = '{tag}' "
            "ORDER BY r.id DESC LIMIT 1"
        )
        if failed_row:
            break
        time.sleep(5)

    report.check("1.6", "scan failure is recorded, not swallowed", "failed" in failed_row,
                 failed_row or "no scan_run row appeared within 180s")

    still_ok = client.get("/health").json().get("status") == "ok"
    report.check("1.7", "a failing image does not wedge the queue", still_ok,
                 "health still ok after the failure")


# --------------------------------------------------------------------------
# Task 2 -- Database Design
# --------------------------------------------------------------------------
def check_schema(client: httpx.Client, report: Report, use_db: bool) -> None:
    print(f"\n{YELLOW}Task 2 - Database Design{RESET}")

    images = client.get("/api/images", params={"limit": 1000}).json()["items"]
    has_fields = all(
        {"name", "tag", "last_scan_at", "last_scan_status"} <= set(i) for i in images
    )
    report.check("2.1", "images store name, tag, last scan time and status", has_fields)

    cves = client.get("/api/cves", params={"limit": 5}).json()["items"]
    if cves:
        has_cve_fields = all({"cve_id", "max_severity", "title"} <= set(c) for c in cves)
        report.check("2.2", "CVEs store id, severity level and title", has_cve_fields,
                     f"sample: {cves[0]['cve_id']} ({cves[0]['max_severity']})")
    else:
        report.check("2.2", "CVEs store id, severity level and title", False, "no CVEs stored")

    # The image<->CVE relationship is only proven by a CVE that spans images.
    shared = next((c for c in client.get(
        "/api/cves", params={"limit": 200}).json()["items"]
        if c["affected_image_count"] > 1), None)
    report.check("2.3", "image <-> CVE relationship is many-to-many", shared is not None,
                 f"{shared['cve_id']} affects {shared['affected_image_count']} images"
                 if shared else "no CVE found in more than one image")

    if cves:
        affected = client.get(f"/api/cves/{cves[0]['cve_id']}/images").json()["items"]
        has_pkg = affected and all(
            a["package"].get("name") and a["package"].get("version") for a in affected
        )
        report.check("2.4", "package/dependency information is stored", bool(has_pkg),
                     f"{cves[0]['cve_id']} -> {affected[0]['package']}" if affected else "")

    if use_db:
        tables = set(psql(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        ).splitlines())
        expected = {"image", "scan_job", "scan_run", "package", "cve", "finding"}
        report.check("2.5", "expected tables exist", expected <= tables,
                     f"missing: {sorted(expected - tables)}" if expected - tables
                     else f"{len(expected)} tables")


# --------------------------------------------------------------------------
# Task 3 -- REST API
# --------------------------------------------------------------------------
def check_api(client: httpx.Client, report: Report) -> None:
    print(f"\n{YELLOW}Task 3 - REST API{RESET}")

    health = client.get("/health")
    report.check("3.1", "GET /health", health.status_code == 200,
                 f"HTTP {health.status_code}: {health.json().get('status')}")

    images_response = client.get("/api/images")
    images = images_response.json()["items"]
    counts_ok = all(
        i["total_cves"] == sum(i["severity_counts"].values()) for i in images
    )
    report.check("3.2", "GET /api/images returns summary statistics",
                 images_response.status_code == 200 and counts_ok,
                 "per-severity counts sum to total_cves" if counts_ok
                 else "severity counts do not sum to total_cves")

    scanned = max(images, key=lambda i: i["total_cves"], default=None)
    if scanned is not None and scanned["total_cves"] == 0:
        scanned = None
    if scanned is None:
        report.check("3.3", "GET /api/images/:name/:tag/cves", False, "no image with findings")
        report.check("3.4", "  ... ?severity= filter", False, "no image with findings")
    else:
        path = f"/api/images/{scanned['name']}/{scanned['tag']}/cves"
        unfiltered = client.get(path, params={"limit": 1000})
        report.check("3.3", "GET /api/images/:name/:tag/cves",
                     unfiltered.status_code == 200,
                     f"{unfiltered.json()['pagination']['total']} CVEs in "
                     f"{scanned['name']}:{scanned['tag']}")

        target = max(scanned["severity_counts"],
                     key=lambda k: scanned["severity_counts"][k] if k != "UNKNOWN" else -1)
        filtered = client.get(path, params={"severity": target, "limit": 1000}).json()
        only_target = all(f["severity"] == target for f in filtered["items"])
        expected = scanned["severity_counts"][target]
        report.check("3.4", "  ... ?severity= filter is honoured",
                     only_target and filtered["pagination"]["total"] == expected,
                     f"severity={target}: {filtered['pagination']['total']} returned, "
                     f"{expected} expected from the summary")

    cves_response = client.get("/api/cves", params={"limit": 1000})
    cve_items = cves_response.json()["items"]
    report.check("3.5", "GET /api/cves lists unique CVEs across all images",
                 cves_response.status_code == 200
                 and len({c["cve_id"] for c in cve_items}) == len(cve_items),
                 f"{cves_response.json()['pagination']['total']} unique CVEs")

    critical = client.get("/api/cves", params={"severity": "CRITICAL", "limit": 1000}).json()
    report.check("3.6", "  ... ?severity= filter is honoured",
                 all(c["max_severity"] == "CRITICAL" for c in critical["items"]),
                 f"{critical['pagination']['total']} CRITICAL CVEs")

    if cve_items:
        cve_id = cve_items[0]["cve_id"]
        affected = client.get(f"/api/cves/{cve_id}/images")
        items = affected.json()["items"]
        report.check("3.7", "GET /api/cves/:cve_id/images includes package details",
                     affected.status_code == 200 and bool(items)
                     and all("package" in a for a in items),
                     f"{cve_id} affects {len(items)} image(s)")
    else:
        report.check("3.7", "GET /api/cves/:cve_id/images", False, "no CVEs to query")

    # Error handling is not in the brief, but a reviewer will try these.
    report.check("3.8", "unknown image returns 404",
                 client.get("/api/images/nope/nope/cves").status_code == 404)
    report.check("3.9", "unknown CVE returns 404",
                 client.get("/api/cves/CVE-0000-0000/images").status_code == 404)
    report.check("3.10", "invalid severity returns 400",
                 client.get("/api/cves", params={"severity": "SEVERE"}).status_code == 400)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--wait", type=int, default=0,
                        help="Seconds to wait for every image to be scanned first.")
    parser.add_argument("--with-db", action="store_true",
                        help="Also run SQL and failure-path checks via docker compose.")
    args = parser.parse_args()

    print(f"Verifying {args.base_url} against docs/ASSIGNMENT-REQUIREMENTS.md")

    client = httpx.Client(base_url=args.base_url, timeout=30.0)
    try:
        client.get("/health")
    except httpx.HTTPError as exc:
        print(f"\n{RED}Cannot reach the API at {args.base_url}{RESET}\n  {exc}")
        print("\nStart the stack first:  docker compose up --build")
        return 2

    if args.wait:
        print(f"\n{YELLOW}Waiting up to {args.wait}s for scans to complete{RESET}")
        if not wait_for_scans(client, args.wait):
            print(f"  {YELLOW}not all images scanned; checking what landed anyway{RESET}")

    report = Report()
    check_scanner(client, report, args.with_db)
    check_schema(client, report, args.with_db)
    check_api(client, report)
    return report.summary()


if __name__ == "__main__":
    sys.exit(main())
