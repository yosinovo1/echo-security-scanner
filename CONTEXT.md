# Domain glossary

The vocabulary this project uses. Terms here are about the domain, not the code:
if a word means something specific in a security-scanning context, it is pinned down
here so the API, the schema and the conversation all use it the same way.

## Image

A container image the system is responsible for watching, identified by the pair
**(name, tag)** — for example `nginx` + `1.19`.

An Image is a *subscription*, not an artifact: it names something to keep scanning.
The artifact it currently points at is the [Digest](#digest), and that can change
underneath a stable name and tag.

### Failure streak

How many consecutive [Scan Jobs](#scan-job) for an Image have been *exhausted* —
given up on after using all their attempts. Any Success or Skip resets it to zero.

It counts exhausted Jobs rather than failed attempts, because a Job already retries
internally: a single bad minute at a registry should not read as a failing Image. The
streak is what widens the interval between attempts, so an Image whose reference has
genuinely disappeared is retried about once a day instead of every fifteen minutes —
while still recovering by itself if the reference comes back, which is why the streak
slows an Image down rather than switching it off.

## Tag

The mutable half of an Image's identity. A tag is a pointer maintained by whoever
publishes the image, and it can be moved to new content at any time without warning.
Two scans of the same tag on different days may describe entirely different bytes.

## Digest

The content address (`sha256:…`) of the bytes a scan actually examined. Unlike a
Tag, a Digest is immutable: the same digest is always the same image.

Findings describe a Digest. Saying "nginx:1.19 has 47 CVEs" is shorthand; the precise
claim is "the digest that nginx:1.19 pointed at when we scanned it has 47 CVEs".

**Tag drift** is the event where an Image's Digest changes while its name and tag stay
the same — new content is live wherever that tag is deployed.

## Scan Job

A unit of work: an intention to scan one Image. A Scan Job is queued, claimed,
and either completed, retried, or abandoned.

An Image has at most one *active* (queued or in-progress) Scan Job at a time.

### Time-sensitive

A property of a Scan Job meaning it should be done ahead of routine work. It changes
*ordering* only. It does not entitle a job to exceed the
[Backpressure](#backpressure) from a registry, or to repeat a scan whose result is
already known.

## Scan Run

One attempt to scan an Image, and its outcome. Every attempt produces a Scan Run,
including the ones that fail — the record of failures is part of the product, not a
side effect of logging.

A Scan Run ends in one of three outcomes:

- **Success** — Trivy ran and produced results.
- **Skipped** — the scan was provably unnecessary (see [Unchanged](#unchanged)).
- **Failed** — the attempt could not produce results.

A Scan Run records the Digest it examined, so its findings remain interpretable even
after the Tag moves.

### Unchanged

The condition under which a scan cannot produce a different answer than the last
successful one: the same Digest, the same scanner, the same vulnerability database,
and the same scan settings. "Unchanged" is a statement about *content*, never about
elapsed time — an image scanned three hours ago may be Unchanged, while one scanned
two minutes ago may not be if the vulnerability database moved in between.

## CVE

A publicly catalogued vulnerability, identified by its CVE ID. A CVE is a global fact
about the world: it exists whether or not any watched Image contains it.

## Package

A piece of software installed inside an Image, identified by name, version, and
ecosystem (an OS package manager such as Debian or Alpine, or a language ecosystem
such as Python or npm). The same package name can exist in more than one ecosystem
and they are not the same Package.

## Finding

The pairing of a [CVE](#cve) with the [Package](#package) that carries it in a
specific [Image](#image). A Finding is what scanning actually discovers; a CVE by
itself affects nothing in particular.

### Current

A Finding is Current when it was reported by the Image's most recent successful
[Scan Run](#scan-run). A Finding that stops being reported is not deleted — it stays
as history, recording that the vulnerability was once present and is no longer.

"How many CVEs does this image have" always means Current Findings.

## Severity

How serious a vulnerability is, as one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or
`UNKNOWN`.

**Severity is a property of a Finding, not of a CVE.** Distributions rate the same
CVE differently based on how they build and configure the affected package, so one
CVE can legitimately be `HIGH` in one Image and `MEDIUM` in another. Both ratings are
correct for their context.

### Maximum severity

A CVE's severity rolled up across every Image where it is [Current](#current): a CVE
is `CRITICAL` if it is `CRITICAL` in any scanned Image. This exists so that a
question about a CVE in isolation ("list all CRITICAL CVEs") has a defined answer.
It is a derived summary, and the per-Finding Severity remains the ground truth.

## Backpressure

A registry declining to serve us *right now* because we are asking too often.

Backpressure is **not** [failure](#scan-run). A failure says the work cannot be done;
backpressure says it cannot be done *yet*. The distinction is operational, not
pedantic: a Scan Job that fails spends one of its finite attempts and eventually gives
up, whereas one that meets backpressure is deferred at no cost and will be tried
again. Treating the second as the first would let a busy hour at a registry retire
every Image in the system as permanently failed.

The system does not predict backpressure or budget against it — the registry is the
only party that knows its own limits, and it reports them (an HTTP `429`, usually with
a `Retry-After`). At scale the registry, rather than available compute, is what limits
how often Images can be scanned.
