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
minutes: every image is due immediately on a cold start, so the queue fills at once
and drains at worker-pool rate, and the first scan of each image pays for a cold
layer pull. Subsequent rounds take seconds per image.

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

```

| Table | Holds |
|---|---|
| `image` | The watch list: `(name, tag)`, optional per-image interval, and pointers to the current run and last scan status. |
| `scan_job` | The queue. Status, priority, `scheduled_for`, `lease_until`, `attempts`. |
| `scan_run` | One row per attempt, with the four fields that form the skip invariant plus duration and error. |
| `package` | `(name, version, type)` — `type` is the ecosystem, so `openssl` as a Debian package and as a Python package are distinct. |
| `cve` | Global CVE facts plus the derived `max_severity` rollup. |
| `finding` | The join that matters: a CVE in a package in an image, with **its own severity**, `fixed_version`, and `first_seen_run_id` / `last_seen_run_id`. |

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

### No cold-start jitter, because the queue already absorbs the burst

An earlier version spread never-scanned images across a window with a deterministic
`hash(image_id)` offset. It was removed: **enqueueing is not scanning.**

A thousand due images become a thousand queue rows in one `INSERT`, not a thousand
concurrent scans. Real concurrency is bounded by worker replica count and by the
registry itself, both downstream of the scheduler, so spreading the enqueue changed
nothing a worker, Postgres or `trivy-server` could observe — it only delayed the
first results and gave a manually added image a mystery delay before its first scan.
Steady-state spread is not lost either: it comes from the rate at which the queue
drains, which is what sets each image's `last_scan_at` in the first place.

It also failed to cover the burst that actually happens in production. The jitter
applied only to the never-scanned branch, so after an outage — every image overdue,
`last_scan_at` set — the whole fleet became due on the first tick regardless. If
thundering herd were a real problem here, that is the case worth solving, and the
answer would be clamping catch-up rather than jittering first scans.

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

### The registry is the binding constraint — but it is not ours to model

Ten images every fifteen minutes is already a few hundred registry requests per
six-hour window, and registries throttle anonymous clients well below that. At a
thousand images it is not close. That much is right, and it is why a throttled job is
**deferred, not failed**: backpressure must never burn a job's retry allowance, or a
slow afternoon at Docker Hub walks the whole fleet to permanently failed.

The first design drew the wrong conclusion from it. It carried a Postgres token
bucket (`registry_budget`) that modelled Docker Hub's anonymous ceiling locally —
100 requests per six hours — and deferred jobs when the *local* count ran out.

**It was deleted after running it.** Three reasons, ascending:

1. **The constant was a guess at someone else's number.** Docker Hub's anonymous
   limit has changed repeatedly, is scoped per-IP for anonymous clients, and differs
   by authentication state. Any value compiled in here is wrong behind a different
   NAT. The giveaway was the footnote this section used to carry: *"check the current
   figures before tuning."* A limiter whose documentation tells you to go verify its
   central constant against an external source is not a limiter — it is a stale cache
   of a fact we do not own.

2. **It was a second source of truth,** which is precisely the argument made against
   a broker two sections up. The registry holds the authoritative count; we kept a
   divergent local replica and reconciled it with nothing.

3. **It caused a worse outage than the limit it modelled.** This is the one that
   settled it. Left running for three hours, the stack reported:

   ```
   registry-1.docker.io | tokens=0 | capacity=100 | elapsed=02:59:44
   ```

   Ten images at a fifteen-minute cadence need **240** manifest requests per six-hour
   window against a modelled capacity of **100**, so the budget ran dry a third of the
   way in and every job sat `pending` with `registry budget exhausted`. No image was
   scanned for the rest of the window, `/health` still answered `ok`, and the API went
   on serving three-hour-old findings as current. The protection was doing more damage
   than the throttling it existed to prevent — and it was doing it silently, which for
   a security tool is the worst available failure mode.

   Worse, it was charging for something free: Docker Hub counts manifest **GET**s, and
   documents `HEAD` as the way to check your allowance *without* spending it. The skip
   path — 72 of 90 runs on that stack — was paying a toll that does not exist.

**What replaced it is the registry's own answer.** A `429` raises `RateLimited`
carrying the registry's `Retry-After`, and the worker defers for exactly that long.
Trivy's pulls are classified the same way, from stderr, in
[`parser.is_rate_limit_error`](app/scanner/parser.py) — matching on prose is fallible,
so it lives in the fixture-tested module rather than at the subprocess boundary, and
the markers deliberately exclude a bare `429` because layer digests contain those
characters.

Net effect: one table, one module and two config knobs removed, and backpressure is
now driven by the only party that actually knows the limit.

> At a thousand images none of this is sufficient on its own — that workload needs
> ~24,000 manifest requests per window against an anonymous ceiling of ~100. The
> answer there is authentication or a pull-through mirror, not a smarter counter. See
> [Known limitations](#known-limitations).

### Time-sensitive reorders work; it never skips safety gates

A time-sensitive job jumps the priority lane and ignores "not due yet". It still
yields to a registry that is throttling us, and it is still skipped if the content
invariant holds.
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
| `SCANNER_TRIVY_SERVER_URL` | set in compose | Enables client mode. **Required for more than one worker** — see the contention measurement above. |
| `SCANNER_LEASE_SECONDS` | `1200` | After this a claimed job is presumed dead and reclaimed. Must exceed the scan timeout, or a slow scan loses its lease mid-flight and gets duplicated onto another worker — enforced at startup. |
| `SCANNER_MAX_ATTEMPTS` | `5` | Retries before a job is marked failed. A nonexistent image fails immediately. A registry throttling us does not count as an attempt at all. |
| `SCANNER_PAGE_SIZE_DEFAULT` / `_MAX` | `100` / `1000` | Pagination. |

### Adding or retuning images

```sql
INSERT INTO image (name, tag) VALUES ('ghcr.io/acme/api', 'v2');
UPDATE image SET scan_interval_seconds = 300 WHERE name = 'nginx';
UPDATE image SET enabled = false WHERE name = 'mongo';
```

The scheduler picks up changes on its next tick, and a newly added image is due
immediately — it is enqueued on that tick rather than after a delay.

---

## Tests

```bash
pip install -r requirements-dev.txt

pytest                                  # 89 with Postgres; 70 pass/19 skip without
ruff check app tests scripts            # lint
python scripts/check_schema_drift.py    # models vs. the hand-written migration
```

Runs without Docker: 70 tests pass and the 19 database-backed ones skip cleanly.
With Postgres reachable, all 89 run:

```bash
docker compose up -d postgres
SCANNER_POSTGRES_HOST=localhost pytest      # 89 passed
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
- **`test_scheduling.py`** covers due-time arithmetic, the skip invariant — including
  the case a time-based heuristic gets wrong (fresh vulnerability DB, unchanged
  image) — and the lease/timeout configuration guard.
- **`test_registry.py`** drives the registry client over `httpx.MockTransport`, so it
  runs offline: reference parsing, the bearer-token challenge, and the throttling path
  that replaced the token bucket — `429` on both the manifest *and* the token
  endpoint, and `Retry-After` in both the delta-seconds and HTTP-date forms.
- **`test_trivy.py`** pins exit-code classification only. Throttling and failure both
  exit 1, and confusing them is silent in both directions.
- **`test_queue.py`** runs against real Postgres, because the queue's behaviour *is*
  PostgreSQL semantics: `SKIP LOCKED` and partial unique indexes. Testing it against
  SQLite would prove nothing.

---

## Known limitations

- **The Trivy subprocess boundary is only thinly tested** — exit-code classification
  is pinned (`tests/test_trivy.py`), because confusing throttling with failure is
  silent in both directions. Argv construction and real process behaviour are not
  covered; `app/scanner/trivy.py` is kept tiny specifically so that surface stays
  trivial.
- **The Trivy fixtures are hand-authored** to the documented schema rather than
  captured from a live run. Re-capture them with
  `trivy image --format json nginx:1.19` before trusting them as a regression
  baseline.
- **Pagination is `limit`/`offset`**, which degrades on deep pages. Result sets here
  top out in the tens of thousands, so keyset pagination is the scale-up path rather
  than a present need.
- **Registry authentication is anonymous only.** Private registries would need
  credentials threaded through `app/registry/digest.py` and into the Trivy
  invocation. This is also the real answer to registry throttling at scale: an
  authenticated account, or a pull-through mirror, raises the ceiling by orders of
  magnitude where tuning a client-side limit cannot.
- **Scaling is replica count**, a consequence of one-scan-per-process. Roughly 1000
  images at a 15-minute cadence implies dozens of worker processes — and at that
  point `trivy-server` becomes the next thing to measure, since every worker scans
  through it.
