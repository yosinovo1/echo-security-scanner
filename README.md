# Container Security Scanner

Scans container images for CVEs with [Trivy](https://github.com/aquasecurity/trivy)
on a schedule, stores the findings in PostgreSQL, and serves them over a REST API.

Built against [the assignment brief](docs/ASSIGNMENT-REQUIREMENTS.md), but designed for the shape
the problem takes at a thousand images rather than ten — which changes several
answers, each explained under [Design decisions](#design-decisions).

---

## Quick start

**Prerequisites:** Docker and Docker Compose. Nothing else — no local Python, no
local Trivy, and no Docker socket is mounted into any container.

```bash
docker compose up --build
```

That brings up Postgres, runs migrations, seeds the brief's ten images, downloads the
Trivy vulnerability database once into a shared volume, and starts the API, the
scheduler, and two workers.

```bash
curl localhost:8000/health
```

Interactive API docs: **http://localhost:8000/docs**

First run downloads the ~1.3 GB Trivy vulnerability database, so allow a couple of
minutes before scanning begins. All ten images are then scanned in roughly five
minutes — cold-start scans are spread over `SCANNER_INITIAL_SPREAD_SECONDS` (120 by
default) rather than the full interval, and the first scan of each image pays for a
cold layer pull. Subsequent rounds take seconds per image.

### Watching it work

```bash
# Queue state, live
docker compose exec postgres psql -U scanner -d scanner \
  -c "SELECT j.id, i.name || ':' || i.tag AS image, j.status, j.priority, j.attempts
        FROM scan_job j JOIN image i ON i.id = j.image_id ORDER BY j.id;"

# Scan history, including failures and skips
docker compose exec postgres psql -U scanner -d scanner \
  -c "SELECT i.name || ':' || i.tag AS image, r.status, r.duration_ms,
             left(r.digest, 20) AS digest, r.error
        FROM scan_run r JOIN image i ON i.id = r.image_id
       ORDER BY r.id DESC LIMIT 20;"

# More workers
docker compose up -d --scale worker=6
```

---

## Architecture

```
                    ┌──────────────┐
                    │  scheduler   │  advisory-locked singleton
                    │              │  inserts due jobs, reaps dead leases
                    └──────┬───────┘
                           │ INSERT scan_job
                           ▼
  ┌────────┐        ┌──────────────┐        ┌──────────────────┐
  │  api   │───────▶│  PostgreSQL  │◀───────│  worker × N      │
  │        │  reads │              │ claims │  one scan/process│
  └────────┘        │  data + queue│        └────────┬─────────┘
                    └──────────────┘                 │ trivy image
                                                     ▼
                                            ┌──────────────────┐
                                            │  image registry  │
                                            └──────────────────┘
                    ┌──────────────────┐
                    │   trivy-server   │◀── workers scan through it
                    │  owns the vuln DB│    (never open it themselves)
                    └──────────────────┘
```

| Service | Role |
|---|---|
| `api` | FastAPI, read-only. **No Trivy in this image** — it stays small and scan load never competes with request latency. |
| `scheduler` | Decides which images are due and enqueues them. Safe to run several replicas: losers of the advisory lock stand by, giving failover without leader election. |
| `worker` | Claims one job, scans, writes, repeats. Synchronous and single-job by design. |
| `trivy-server` | Owns the vulnerability database. Workers scan through it as thin clients — see [the contention measurement](#trivy-runs-in-clientserver-mode-measured-not-assumed). |
| `postgres` | Findings **and** the job queue. |

---

## API

All collection endpoints return `{ "items": [...], "pagination": {...} }` and accept
`limit` (default 100, max 1000) and `offset`. Responses carry `ETag` and
`Last-Modified`; send `If-None-Match` to get a `304`.

### `GET /health`

```bash
curl -s localhost:8000/health | jq
```
```json
{
  "status": "ok",
  "database": "ok",
  "images_enabled": 10,
  "jobs_pending": 3,
  "last_successful_scan_at": "2026-09-14T10:42:07.512Z"
}
```

Reports queue depth and last successful scan, not just connectivity — an API that
answers while no scan has succeeded in hours is not healthy.

### `GET /api/images`

All scanned images with per-severity counts.

```bash
curl -s localhost:8000/api/images | jq
```
```json
{
  "items": [
    {
      "name": "alpine",
      "tag": "3.12",
      "digest": "sha256:c0e9560cda118f9ec63ddefb4a173a2b2a0347082d7dff7dc14272e7841a5b5a",
      "last_scan_at": "2026-09-14T10:41:55.201Z",
      "last_scan_status": "success",
      "scan_interval_seconds": 900,
      "total_cves": 4,
      "severity_counts": { "CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 0 }
    }
  ],
  "pagination": { "total": 10, "limit": 100, "offset": 0 }
}
```

### `GET /api/images/{image_name}/{tag}/cves`

CVEs in one image. Optional `?severity=CRITICAL|HIGH|MEDIUM|LOW`.

```bash
curl -s "localhost:8000/api/images/nginx/1.19/cves?severity=CRITICAL" | jq
curl -s "localhost:8000/api/images/bitnami/redis/6.0/cves" | jq   # slashes work
```
```json
{
  "items": [
    {
      "cve_id": "CVE-2021-3711",
      "title": "openssl: SM2 Decryption Buffer Overflow",
      "severity": "CRITICAL",
      "package": { "name": "libssl1.1", "version": "1.1.1d-0+deb10u5", "type": "debian" },
      "fixed_version": "1.1.1d-0+deb10u7",
      "first_seen_at": "2026-09-13T08:15:02.000Z",
      "last_seen_at": "2026-09-14T10:41:55.201Z"
    }
  ],
  "pagination": { "total": 1, "limit": 100, "offset": 0 }
}
```

`fixed_version: null` means no fix has been published — meaningfully different from a
fix that exists but is not applied.

### `GET /api/cves`

Every unique CVE across all images. Optional `?severity=`.

```bash
curl -s "localhost:8000/api/cves?severity=CRITICAL&limit=5" | jq
```
```json
{
  "items": [
    {
      "cve_id": "CVE-2021-3711",
      "title": "openssl: SM2 Decryption Buffer Overflow",
      "max_severity": "CRITICAL",
      "published_at": "2021-08-24T15:15:00Z",
      "last_modified_at": "2022-04-05T18:15:00Z",
      "affected_image_count": 3
    }
  ],
  "pagination": { "total": 41, "limit": 5, "offset": 0 }
}
```

`max_severity` is a **rollup**, not a single vendor's rating — see
[Severity](#severity-belongs-to-the-finding-not-the-cve).

### `GET /api/cves/{cve_id}/images`

Every image affected by one CVE, with the package that carries it.

```bash
curl -s localhost:8000/api/cves/CVE-2021-3711/images | jq
```
```json
{
  "items": [
    {
      "name": "nginx",
      "tag": "1.19",
      "digest": "sha256:df13abe416e37eb3db4722840dd479b00ba193ac6606e7902331dcea50f4f1f2",
      "severity": "CRITICAL",
      "package": { "name": "libssl1.1", "version": "1.1.1d-0+deb10u5", "type": "debian" },
      "fixed_version": "1.1.1d-0+deb10u7",
      "last_seen_at": "2026-09-14T10:41:55.201Z"
    }
  ],
  "pagination": { "total": 3, "limit": 100, "offset": 0 }
}
```

The same CVE may show a **different severity per image** — that is correct, not a
bug. Debian and Alpine rate the same CVE differently.

### `POST /api/images/{image_name}/{tag}/scan` *(beyond the brief)*

```bash
curl -X POST "localhost:8000/api/images/nginx/1.19/scan?time_sensitive=true"
```
```json
{ "status": "queued", "job_id": 42, "time_sensitive": true }
```

`status` is `queued`, `promoted` (a job was already waiting and jumped the lane), or
`already_queued`. Included because without a trigger, the priority lane would be a
column nothing ever sets.

---

## Database schema

```
image ──┬──< scan_job          one active job per image, enforced by a partial
        │                      unique index on (image_id) WHERE status IN
        │                      ('pending','running')
        │
        ├──< scan_run          every attempt: success, skipped, or failed
        │                      records digest + trivy version + db version + flags
        │
        └──< finding >── cve
                 │
                 └──── package

registry_budget                token bucket, one row per registry host
```

| Table | Holds |
|---|---|
| `image` | The watch list: `(name, tag)`, optional per-image interval, and pointers to the current run and last scan status. |
| `scan_job` | The queue. Status, priority, `scheduled_for`, `lease_until`, `attempts`. |
| `scan_run` | One row per attempt, with the four fields that form the skip invariant plus duration and error. |
| `package` | `(name, version, type)` — `type` is the ecosystem, so `openssl` as a Debian package and as a Python package are distinct. |
| `cve` | Global CVE facts plus the derived `max_severity` rollup. |
| `finding` | The join that matters: a CVE in a package in an image, with **its own severity**, `fixed_version`, and `first_seen_run_id` / `last_seen_run_id`. |
| `registry_budget` | Remaining request allowance per registry host. |

**A finding is "current" iff `finding.last_seen_run_id = image.current_scan_run_id`.**
Every read path filters on this. Findings are never deleted: one that stops being
reported simply stops having `last_seen_run_id` advanced, which preserves the history
that scanning every 15 minutes exists to produce.

Vocabulary is defined in [CONTEXT.md](CONTEXT.md).

---

## Design decisions

### Postgres is the queue

`SELECT … FOR UPDATE SKIP LOCKED`, not Redis or Celery.

A job's completion and the findings it produced **commit in one transaction**. With
an external broker they are two systems, so the only available guarantee is
at-least-once, and the gap gets papered over with idempotency keys. Here there is no
gap.

Redis was the original plan. It lost its justification once the read cache was
dropped: the brief needs queryable scan status and failure history, so the job table
gets written either way — with a broker, job state lives under a TTL and gets
mirrored into Postgres anyway, giving two sources of truth about one job. Throughput
is not the deciding factor in either direction: peak load at 1000 images is about
**1.1 jobs/sec**, roughly three orders of magnitude under what either system handles.

The cost is about 40 lines: an `attempts` column, backoff arithmetic, and a reaper for
expired leases.

### Skip on a content invariant, not elapsed time

A scan is skipped when the **digest, Trivy version, vulnerability DB version, and
scan flags** all match the last successful run. Those four being equal means the
findings are *necessarily* identical.

The obvious alternative — "skip if scanned less than one interval ago" — is wrong in
both directions:

- it **skips scans that would find something**: the vulnerability database updated
  two minutes ago and the image is newly known to be vulnerable;
- it **runs scans that cannot possibly differ**: nothing has changed in three hours.

The check costs one manifest `HEAD`, not a layer pull.

### Images are `(name, tag)`; digests are recorded per run

The API addresses images by tag because the brief does, but a tag is a mutable
pointer. Every `scan_run` records the digest actually scanned, which buys three
things: findings are reproducible, tag drift is observable (new bytes live under a
stable tag is a security event in itself), and the skip invariant above becomes sound.

### Severity belongs to the finding, not the CVE

Trivy reports vendor severity per target, and Debian, Alpine and NVD routinely
disagree about the same CVE. So `finding.severity` is ground truth, and
`cve.max_severity` is a derived rollup so that `GET /api/cves?severity=` has a
defined meaning.

**The rollup rule: a CVE is CRITICAL if it is CRITICAL in any scanned image.** It is
recomputed after every scan over current findings only.

### The registry is the binding constraint, not the worker pool

Ten images every fifteen minutes is already a few hundred manifest fetches per
six-hour window, and registries throttle anonymous clients well below that. At a
thousand images it is not close.

So every registry touch — digest resolution included — spends a token from a
per-registry bucket, and a throttled job is **deferred, not failed**: backpressure
must not burn a job's retry allowance. The default budget is deliberately
conservative; see [Configuration](#configuration).

> Docker Hub's published anonymous limits have changed over time. Check the current
> figures before tuning `SCANNER_REGISTRY_BUDGET_TOKENS` upward.

### Time-sensitive reorders work; it never skips safety gates

A time-sensitive job jumps the priority lane and ignores "not due yet". It still
spends registry budget, and it is still skipped if the content invariant holds.
Urgency justifies reordering work — never doing provably useless work, and never
getting the IP throttled.

### No read cache

At 1000 images this is roughly 2M finding rows: unremarkable for indexed Postgres,
and the data only changes every 15 minutes. The least cache-friendly endpoint
(`/api/cves/{id}/images`) is precisely the inverted cross-image query a cache serves
worst.

What is avoided is the invalidation surface. A missed invalidation means serving
stale vulnerability data — the one wrong answer a security tool must never give.
`ETag` and `Last-Modified` derived from the newest scan completion give the same
benefit correct by construction, with nothing to go stale.

### Trivy runs in client/server mode — measured, not assumed

The first design shared one Trivy cache volume across workers, each running Trivy
standalone. That is wrong, and running it proved it: the vulnerability database is a
single ~1.3 GB bbolt file, and concurrent openers serialise brutally.

| image | 2 workers, shared cache | 3 workers, client/server |
|---|---|---|
| `nginx:1.19` | 116,566 ms | **3,921 ms** |
| `postgres:12` | 94,473 ms | **4,126 ms** |
| `redis:6.0` | 10,141 ms *(uncontended)* | **2,886 ms** |

So `trivy-server` owns the database and workers are thin clients that never open it.
This is what makes "scale = replica count" actually true; with the shared cache it
was false, and quietly so — nothing errored, throughput just collapsed.

Workers still mount the server's cache read-only at `/trivy-db`, but only to read
`db/metadata.json` for the database version that feeds the skip invariant. Reading
that file never touches the bbolt database, so it cannot contend with a scan.

Each worker keeps its *own* writable Trivy cache at `/trivy-cache`, deliberately
container-local. Trivy stores an artifact cache there and it is a bolt database too:
mounting it read-only makes every scan a cold pull (75s vs 3s, measured), and sharing
one between workers recreates the very contention this section is about.

### One scan per process

A wedged Trivy takes down one worker, not every in-flight scan on the box, and it
removes concurrency control from the worker entirely. Scaling is replica count:
`docker compose up --scale worker=N`.

---

## Configuration

Every setting is a `SCANNER_`-prefixed environment variable (see `app/config.py`).

| Variable | Default | Notes |
|---|---|---|
| `SCANNER_DEFAULT_SCAN_INTERVAL_SECONDS` | `900` | The brief's 15 minutes. Per-image overrides live in `image.scan_interval_seconds`. |
| `SCANNER_SCHEDULER_TICK_SECONDS` | `10` | How often the scheduler looks for due images. |
| `SCANNER_INITIAL_SPREAD_SECONDS` | `120` | Window over which never-scanned images are spread on a cold start. Raise it towards the interval when the image count makes a 2-minute burst significant. |
| `SCANNER_TRIVY_SERVER_URL` | set in compose | Enables client mode. **Required for more than one worker** — see the contention measurement above. |
| `SCANNER_LEASE_SECONDS` | `1200` | After this a claimed job is presumed dead and reclaimed. Must exceed the scan timeout, or a slow scan loses its lease mid-flight and gets duplicated onto another worker — enforced at startup. |
| `SCANNER_MAX_ATTEMPTS` | `5` | Retries before a job is marked failed. A nonexistent image fails immediately. |
| `SCANNER_REGISTRY_BUDGET_TOKENS` | `100` | Requests per window, per registry host. |
| `SCANNER_REGISTRY_BUDGET_WINDOW_SECONDS` | `21600` | Six hours. |
| `SCANNER_PAGE_SIZE_DEFAULT` / `_MAX` | `100` / `1000` | Pagination. |

### Adding or retuning images

```sql
INSERT INTO image (name, tag) VALUES ('ghcr.io/acme/api', 'v2');
UPDATE image SET scan_interval_seconds = 300 WHERE name = 'nginx';
UPDATE image SET enabled = false WHERE name = 'mongo';
```

The scheduler picks up changes on its next tick. Scans are spread with a
**deterministic** jitter (`hash(image_id) % window`) so a cold start does not fire
every image at once, and — unlike random jitter — the spread survives restarts. A
never-scanned image is spread over `SCANNER_INITIAL_SPREAD_SECONDS`; after its first
scan the cadence carries the spread forward on its own.

---

## Tests

```bash
pip install -r requirements-dev.txt

pytest                                  # 66 with Postgres; 47 pass/19 skip without
ruff check app tests scripts            # lint
python scripts/check_schema_drift.py    # models vs. the hand-written migration
```

Runs without Docker: 47 tests pass and the 19 database-backed ones skip cleanly.
With Postgres reachable, all 66 run:

```bash
docker compose up -d postgres
SCANNER_POSTGRES_HOST=localhost pytest      # 66 passed
```

The database-backed tests create their own `scanner_test` database rather than
sharing one with a running stack — `queue.claim` takes the globally next due job, so
sharing would have the tests and the live system stealing each other's work.

### Verifying against the brief

```bash
python scripts/verify_requirements.py --wait 900 --with-db
```

Checks the running system against every requirement in
[the brief](docs/ASSIGNMENT-REQUIREMENTS.md), labelling each result with the
requirement it proves (1.1, 2.3, 3.4 …). `--with-db` additionally registers an
unresolvable image to prove failures are recorded rather than swallowed. Exit code 0
means the stated requirements are demonstrably met.

- **`test_parser.py`** carries the weight. The subprocess boundary is mocked, so
  every decision Trivy output can force is exercised here: severity variance across
  distros, missing and empty `FixedVersion`, `Results: null`, the zero timestamp
  meaning "unknown", duplicate CVEs at the same package grain, and malformed output.
- **`test_scheduling.py`** covers reference parsing, jitter stability, due-time
  arithmetic, and the skip invariant — including the case a time-based heuristic gets
  wrong (fresh vulnerability DB, unchanged image).
- **`test_queue.py`** runs against real Postgres, because the queue's behaviour *is*
  PostgreSQL semantics: `SKIP LOCKED` and partial unique indexes. Testing it against
  SQLite would prove nothing.

---

## Known limitations

- **The Trivy subprocess boundary is not covered by tests** — argv, exit codes, and
  timeouts. `app/scanner/trivy.py` is kept to about a dozen lines specifically so
  this untested surface stays trivial.
- **The Trivy fixtures are hand-authored** to the documented schema rather than
  captured from a live run. Re-capture them with
  `trivy image --format json nginx:1.19` before trusting them as a regression
  baseline.
- **Pagination is `limit`/`offset`**, which degrades on deep pages. Result sets here
  top out in the tens of thousands, so keyset pagination is the scale-up path rather
  than a present need.
- **Registry authentication is anonymous only.** Private registries would need
  credentials threaded through `app/registry/digest.py` and into the Trivy
  invocation — and would also raise the budget ceiling considerably.
- **Scaling is replica count**, a consequence of one-scan-per-process. Roughly 1000
  images at a 15-minute cadence implies dozens of worker processes — and at that
  point `trivy-server` becomes the next thing to measure, since every worker scans
  through it.
