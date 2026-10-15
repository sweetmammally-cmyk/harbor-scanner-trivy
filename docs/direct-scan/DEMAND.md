# DEMAND: Direct Scan API, Scan Cache and DB Lifecycle for harbor-scanner-trivy

Status: DRAFT v0.9 (disk space check dropped, full-disk behaviour, 2026-10-15)
Repo: fork of `goharbor/harbor-scanner-trivy`

---

## 1. Context

We run a PaaS platform. Customer container images live in Harbor and are scanned with Trivy through `harbor-scanner-trivy`.

Problems today:

- The Harbor API cannot filter or query scans by our own data (customer, app, platform).
- Images are rescanned even when nothing new exists in the vulnerability DB.
- When the connection from the scanner to the DB mirror/upstream is stale, Trivy hangs for a very long time before failing, and we cannot see which mirror/proxy was used.
- We have no persistent record of scans, scan timings or scanner health.

## 2. Goals

1. A **direct scan API** used by our backend (possibly Temporal), independent of Harbor's adapter API.
2. A **MongoDB data plane** for scans, discovered platforms, DB state and DB check history.
3. **Digest-keyed scan cache**: skip scans when the image digest was already scanned with a DB that is not older than the current one.
4. A Trivy DB that is **always present and kept fresh**, with fast pre-checks that prevent long hangs, configurable mirrors/proxies and a safe fallback policy.
5. A **queue** with configurable concurrency and a **scan state API**.
6. **Health API** and structured logging with timings, backed by stored data.

## 3. Non-goals

- Replacing Harbor adapter endpoints (`/api/v1/scan`, `/api/v1/scan/{id}/report`, probes). They keep working unchanged.
- A UI. Customers never call this service; only our backend does.
- Changing how Trivy itself scans.

## 4. Decisions so far

| Topic | Decision |
|---|---|
| Caller | Our backend only (maybe Temporal). Service-to-service auth. |
| Registry credentials | One system-level, pull-only robot account configured on the scanner. The scanner runs in the same Docker network as Harbor. Never sent in requests. |
| MongoDB | Hard dependency. If it is down, the service is not ready and the API returns 503. |
| Cache key | Image digest (not tag). Layers are often shared across images. |
| Skip rule | Skip only if last scan's DB `UpdatedAt` >= current DB `UpdatedAt`. |
| Cached response | Return the stored result with a flag saying the DB did not change for this image. |
| DB failure policy | Log, try configured fallback mirrors, then scan with the old DB until fixed. |
| Default severity | HIGH, CRITICAL. |
| Large reports | Summary + report in the document; GridFS when too big. |
| Platform | A Trivy result type (npm, jar, pip, ...). The request says which platforms to scan and which severities. |
| Stored data | Only findings of the requested result types (at the requested severities) are saved to MongoDB. Trivy's full output is not persisted. |
| DB download | Our own Go module (no dependency on Trivy's downloader). Trivy runs with its DB update disabled. |
| Queue | MongoDB-backed is the working assumption. Priority levels deferred until Trivy behaviour has been studied (R&D). |

## 5. REST API (new, `/api/v2`)

All endpoints require a service token in the `Authorization: Bearer` header. This is caller authentication only; registry access uses the robot account.

### 5.1 Trigger scan: `POST /api/v2/scans`

```json
{
  "request_id": "uuid-from-caller",
  "requested_at": "2026-10-14T10:00:00Z",
  "image": { "repository": "customer-123", "name": "app", "tag": "v1.2.0" },
  "customer_ids": ["cust-123"],
  "customer_data": { "app_id": "app-9", "env": "prod" },
  "platforms": ["npm", "jar"],
  "severity": ["HIGH", "CRITICAL"],
  "max_db_age": "3h",
  "force": false
}
```

Fields:

- `request_id`: idempotency key (important for Temporal retries).
- `platforms`: required. The Trivy result types (npm, jar, pip, ...) the caller wants reported.
- `severity`: optional, default `["HIGH","CRITICAL"]`.
- `max_db_age`: how fresh the DB must be for the response to report `freshness: ok` (see section 7.4). Optional, falls back to a server default.
- `force`: always scan, ignore the cache.
- More filters will be added later (reserved).

Responses:

| Case | HTTP | Body |
|---|---|---|
| Scan queued | 202 | `{ "scan_id", "state": "queued" }` |
| Cache hit (see 6) | 200 | the stored result with `"cached": true, "db_unchanged": true` |
| Same digest+options already queued/running | 200 | existing `scan_id` and its state |
| Same `request_id` again | 200 | the original response |
| Queue full | 429 | error with retry hint |
| Mongo unavailable | 503 | error |

Every response that includes a DB section carries:

```json
"db": { "updated_at": "...", "last_upstream_check_at": "...", "freshness": "ok|stale" }
```

### 5.2 Scan state: `GET /api/v2/scans/{scan_id}`

| `state` | HTTP | Meaning for the caller |
|---|---|---|
| `not_found` | 404 | Scan is not here. Submit again. |
| `queued` | 200 | Waiting in the queue. |
| `scanning` | 200 | Trivy is running. |
| `done` | 200 | Finished. Result is included. |
| `failed` | 200 | Finished with an error. `error` is included. |

A `done` result contains:

```json
{
  "scan_id": "...",
  "state": "done",
  "cached": false,
  "image": { "repository": "", "name": "", "tag": "", "digest": "sha256:..." },
  "db": { "updated_at": "", "last_upstream_check_at": "", "freshness": "ok" },
  "summary": { "critical": 0, "high": 0 },
  "platforms": [ { "type": "node", "name": "..." } ],
  "has_more_platforms": true,
  "vulnerabilities": [],
  "timing": { "queue_wait_ms": 0, "scan_ms": 0, "total_ms": 0 }
}
```

### 5.3 Query scans: `GET /api/v2/scans`

Filters: `customer_id`, `digest`, `repository`, `state`, `severity`, `platform`, `from`, `to`, plus paging. This is the filtering Harbor cannot do.

### 5.4 DB status: `GET /api/v2/db`

Current DB version, `updated_at`, `downloaded_at`, `db_age`, `last_upstream_check_at`, `last_confirmed_current_at`, `newer_available`, active source (mirror), mode (`normal` | `degraded`), and the last DB check results.

### 5.5 Health

- `GET /api/v2/health`: detailed health derived from stored data: Mongo connectivity, DB present, DB age and freshness, last upstream check, queue depth, recent scan durations and failure rate, last pre-check result per source.
- Liveness/readiness probes (existing Harbor-style probes kept). Readiness is false while Mongo is unreachable or no DB exists yet.

## 6. Scan flow and cache rules

```
POST /api/v2/scans
  -> auth + validate, idempotency on request_id
  -> resolve digest for repository/name:tag (registry call with robot account)
  -> look up the last successful scan for this digest in the `scans` collection
  -> cache hit if ALL are true:
       - force == false
       - last successful scan exists for this digest
       - last_scan.db_updated_at >= current_db.UpdatedAt
       - last scan covered the requested platforms (superset)
       - last scan covered the requested severities (superset)
       - same Trivy version / scan options version
     => 200 cached result, flagged db_unchanged
  -> else: enqueue (dedupe on digest + options) => 202
worker:
  -> log "triggering scan"
  -> run Trivy with the local DB (no network DB update during scan)
  -> store result, upsert discovered platforms
  -> log "scan done, took X ms"
```

Notes:

- Request time (`requested_at`) is stored for audit and ordering. It is not used to decide whether to skip.
- Trivy already caches per-layer analysis (by layer ID) so shared layers are cheap to re-analyze. Vulnerability matching still runs against the DB on each scan. The digest cache adds whole-image skipping on top.
- Every scan stores the DB `UpdatedAt` it used.
- A later request for a broader scope (more platforms or lower severities than the last scan covered) is a cache miss and triggers a new scan.
- Trivy runs once per scan. Summary counts are kept for all severities of the requested platforms; details are kept only for the requested severities. Only the requested result types are persisted; Trivy's full output is not stored.

## 7. Trivy DB lifecycle

### 7.1 Always have a DB

- DB lives on a persistent volume; a seed DB is baked into the image so a fresh pod can start.
- DB updates are atomic: download to a temp directory, verify, then swap. Scans in flight keep using the previous copy. No scan ever sees a half-written DB.
- Readiness is false until a DB exists.

### 7.2 Update interval

- `SCANNER_DB_CHECK_INTERVAL` (e.g. `1h`, `3h`, `1d`). The `d` suffix must be supported.
- If unset or invalid, the **fallback interval is 3h** and a WARN log says "using fallback interval".
- Each tick: cheap upstream check first (compare the upstream OCI manifest digest with the stored one). Download only if different.
- While the mode is `degraded`, `SCANNER_DB_RETRY_INTERVAL` (default `15m`) applies instead of the check interval. After a successful run the check interval applies again.

### 7.3 Pre-checks before any download (and before the upstream check)

Purpose: fail fast instead of hanging. Implemented in Go with `net/http/httptrace`, not by shelling out to curl.

For each configured source, in order:

1. Log the effective source: repository/mirror URL, route (direct, HTTP proxy or SOCKS5), TLS flags. Credentials redacted.
2. Connect through the configured route: **direct to our own mirror, HTTP proxy, or SOCKS5**. If a proxy is configured, every step goes through it.
3. TLS handshake check: record version, cipher and ALPN result.
4. HTTP/2 request to the registry `/v2/` endpoint, then the DB manifest. Record DNS, connect, TLS, first-byte and total timings, status and negotiated protocol. HTTP/2 is required by default: a source that negotiates HTTP/1.1 fails its pre-check, unless that source has the `allow-http1` option. The negotiated protocol is always recorded.
5. Every stage has its own timeout and the whole check has a deadline.
6. DNS stage: for a direct route, resolve the registry host. For a proxy route the stage is recorded as skipped, because the proxy resolves the registry name; the proxy's DNS and TCP are covered by the connect stage.
7. A failed pre-check records a failure class in the result and the log, so a network path that interferes can be told apart from a failing registry:
   - `dns_failure`
   - `tcp_timeout`, `tcp_refused`, `tcp_error` (other connect errors, for example a proxy refusing the credentials)
   - `tls_reset` (connection reset or closed during the handshake), `tls_timeout` (no response after the ClientHello), `tls_alert` (the peer sent a TLS alert), `tls_cert_invalid` (normal verification failed; the peer certificate's subject, issuer and expiry are recorded), `tls_error`
   - `http2_not_negotiated`, `http_timeout`, `http_error`, `manifest_timeout`, `manifest_error`, `config_error`

   The TLS stage is there to see whether the network path interferes with the handshake. Certificate verification is the normal one (system CA pool); there is no pinning and no skip-verify.

The sources form a pool: an ordered list that can mix public registries (for example Docker Hub, ghcr.io) and our own mirrors, each with its own route.

Every download is gated by the pre-check: a source that fails its pre-check is never downloaded from; the next source is tried. The pre-check is the main safety, not a fixed total timeout.

If all stages pass, download with two limits:

- Stall timeout (`SCANNER_DB_DOWNLOAD_STALL_TIMEOUT`, default 30s): abort if no bytes arrive for that long.
- Overall cap per source (`SCANNER_DB_DOWNLOAD_TIMEOUT`, default 15m): a safety net only, because the pre-check has already proven the path works.

On either limit the download is aborted and the next source is tried. The Java DB has its own cap (`SCANNER_JAVA_DB_DOWNLOAD_TIMEOUT`, default 45m) because its layer is about 7 times larger; the stall timeout is the same for both.

If a stage fails: log the failure with the stage and timings, store it, move to the next configured fallback source. Authorization headers and tokens never appear in logs.

### 7.4 Failure policy and freshness

- Update loop, per source in order: pre-check, then upstream check, then download and install when the digest differs from the installed one. The loop stops when a source's digest equals the installed one or when a DB was installed. A failed source is recorded with its failure class and the loop goes on to the next source.
- There is no downgrade guard: the first source that answers is trusted, even a mirror a few hours behind upstream.
- A source has answered when its pre-check and upstream check succeeded.
- Two timestamps:
  - `last_upstream_check_at`: set whenever any source answered. Diagnostic only.
  - `last_confirmed_current_at`: set only when the installed DB's digest equals the answering source's digest, or when a new DB was just installed.
- `newer_available`: set when a source offered a different digest and no download could be installed. Cleared by the next successful install or confirmed-current check. A run where no source answered leaves it unchanged.
- A write error on our own disk during install (for example a full disk) fails that source with class `install_error`, leaves no partial directory and keeps the old DB; when no other source installs, the result is `degraded` with `newer_available`. There is no free-space check before downloading.
- No source answered: log ERROR once, set mode `degraded`, keep scanning with the existing DB, keep retrying until fixed.
- A newer DB was offered but none could be installed: set mode `degraded` and `newer_available`, log ONE ERROR "newer DB available but could not be installed" with each source's failure class, keep scanning with the existing DB. Responses say `stale`.
- `db.freshness` in responses: `stale` while `newer_available` is set, regardless of `max_db_age`. Otherwise `ok` if the DB was confirmed current within `max_db_age`, measured from `last_confirmed_current_at` (not from `UpdatedAt`, because upstream may simply not have published a newer DB). "Upstream" here means the first source that answered. Otherwise `stale`.
- DB age (now minus the installed DB's `metadata.json` `UpdatedAt`) is reported separately as `db_age` in `GET /api/v2/db` and in the health output. After each check, when the age is above `SCANNER_DB_AGE_WARN`, a WARN log gives the age and the active source. This is for visibility only and never blocks an install.
- If the request's `max_db_age` is exceeded, the service attempts one refresh (single-flight, bounded by the pre-check and download timeouts). On failure the scan proceeds with the old DB and the response says `stale`.

Java DB has its own optional source list (`SCANNER_JAVA_DB_SOURCES`, same format) and follows the same pre-check and fallback flow. Without Java sources there is no Java DB at all, not even the seed.

### 7.5 Own DB download module

- The scanner downloads the Trivy DB itself as an OCI artifact (manifest, then the DB layer, which is extracted to Trivy's DB directory with `trivy.db` and `metadata.json`).
- Because we own the download path, the same route (direct, HTTP proxy, SOCKS5) is used for pre-checks and for the download. There is no second code path that can behave differently.
- Trivy is then run with its own DB update disabled, so it never tries to download anything during a scan.
- The module verifies content digests, writes to a temp directory and swaps atomically (see 7.1).

## 8. Platforms

- A platform is a Trivy result type (npm, jar, pip, and so on, including OS types such as debian or alpine).
- The request lists the platforms to scan and report on. Only findings of those platforms (at the requested severities) are stored as details and returned. For example, a request for `["npm"]` does not return base-image OS findings.
- Each result lists the `platforms` that were reported and a flag `has_more_platforms`: true when the image contains other platform types than the ones requested.
- A separate `platforms` collection is upserted whenever a platform type is discovered in any scan, requested or not, so the full set is visible at a glance (first seen, last seen, count, example digest).

## 9. Queue

- Scans are queued, then executed by a configurable number of workers.
- Config: worker count, max queue length (full queue returns 429), per-scan timeout.
- Identical work (same digest and options) is deduplicated: callers share one `scan_id`.
- Jobs survive restarts; a worker lease/heartbeat lets other replicas recover jobs from a dead worker.
- Working assumption: the queue is stored in MongoDB (the `scans` collection is the job record).
- Priority levels are deferred: the owner will study Trivy's behaviour first (R&D). The schema reserves an optional `priority` field so adding it later is not a migration.

## 10. Data plane (MongoDB, draft)

`scans` (also acts as the job record)

```json
{
  "_id": "scan_id", "request_id": "", "requested_at": "",
  "customer_ids": [], "customer_data": {},
  "image": { "repository": "", "name": "", "tag": "", "digest": "" },
  "options": { "platforms": ["npm"], "severity": ["HIGH","CRITICAL"] },
  "state": "queued|scanning|done|failed",
  "trivy": { "version": "", "db_updated_at": "", "db_manifest_digest": "" },
  "platforms": [], "has_more_platforms": false,
  "summary": {}, "report": {}, "report_gridfs_id": null,
  "queued_at": "", "started_at": "", "finished_at": "",
  "queue_wait_ms": 0, "scan_ms": 0, "total_ms": 0,
  "worker": "", "lease_until": "", "error": ""
}
```

`platforms`: `{ _id, first_seen_at, last_seen_at, seen_count, example_digest }`

`db_state` (single document): version, `updated_at`, `downloaded_at`, manifest digest, `last_upstream_check_at`, active source, mode.

`db_checks`: history of pre-checks and downloads (source, route, per-stage timings, result, at). TTL index to expire old rows.

Indexes (draft): `scans.request_id` (unique), `scans(image.digest, state, finished_at)`, `scans(customer_ids, finished_at)`, `scans(state, queued_at)`.

Large reports: summary plus report inline; move the full report to GridFS above a size threshold (16 MB BSON limit).

## 11. Configuration (draft)

| Variable | Purpose |
|---|---|
| `SCANNER_V2_API_ENABLED` | Feature flag for the new API |
| `SCANNER_V2_AUTH_TOKEN` | Service token for the new API |
| `SCANNER_MONGO_URI`, `SCANNER_MONGO_DB` | MongoDB. Required, no defaults. If the v2 API is enabled and either is missing, startup fails with a clear error. |
| `SCANNER_REGISTRY_URL` | Harbor URL used to resolve digests and pull images |
| `SCANNER_REGISTRY_USERNAME`, `SCANNER_REGISTRY_PASSWORD` | Robot account (secret) |
| `SCANNER_DB_CHECK_INTERVAL` | `1h`, `3h`, `1d`... fallback `3h` |
| `SCANNER_DB_SOURCES` | Required when the v2 API is enabled (startup fails if empty). Ordered pool of sources: `repo\|route[\|options],...`, route is `direct`, `http://host:port` or `socks5://host:port`; options is an optional `;`-separated list, today only `allow-http1` (pass the pre-check over HTTP/1.1). Example: `mirror.local/aquasec/trivy-db:2\|direct\|allow-http1,ghcr.io/aquasecurity/trivy-db:2\|socks5://proxy:1080` |
| `SCANNER_JAVA_DB_SOURCES` | Optional, same format, for the Java DB. Empty means no Java DB at all: nothing is downloaded and the Java seed is not installed |
| `SCANNER_PRECHECK_TIMEOUT_DNS`, `_CONNECT`, `_TLS`, `_HTTP`, `_MANIFEST`, `_TOTAL` | Pre-check timeouts per stage and overall. Defaults 5s, 5s, 5s, 10s, 10s, 30s |
| `SCANNER_DB_SEED_DIR`, `SCANNER_JAVA_DB_SEED_DIR` | Seed DB baked into the image, installed when no DB exists yet (with no digest, so the first update downloads). Defaults `/home/scanner/seed/db` and `/home/scanner/seed/java-db`. A missing directory means no seed; the service is then not ready until the first download succeeds |
| `SCANNER_DB_DOWNLOAD_STALL_TIMEOUT` | Abort a download when no bytes arrive for this long. Default 30s |
| `SCANNER_DB_DOWNLOAD_TIMEOUT` | Overall cap per source per download of the Trivy DB (safety net). Default 15m |
| `SCANNER_JAVA_DB_DOWNLOAD_TIMEOUT` | Same for the Java DB. Default 45m |
| `SCANNER_DB_RETRY_INTERVAL` | Check interval while the mode is `degraded`. Default 15m |
| `SCANNER_DB_AGE_WARN` | Log a WARN after a check when the installed DB's `UpdatedAt` is older than this. Visibility only. Default `7d` (the `d` suffix is supported) |
| `SCANNER_DB_MAX_AGE_DEFAULT` | Default for `max_db_age`. Default 6h |
| `SCANNER_QUEUE_WORKERS`, `SCANNER_QUEUE_MAX_LENGTH` | Queue settings. Defaults 1 and 100 |
| `SCANNER_SCAN_TIMEOUT` | Per-scan timeout. Default 10m |

All defaults can be overridden by env. Existing Trivy variables keep their current behavior.

## 12. Logging and observability

- Structured logs with `scan_id`, `digest`, `customer_ids`.
- Required lines: "triggering scan", "scan done" with duration, "scan skipped (db unchanged)", DB source selection, each pre-check stage result, "using fallback interval", "all DB sources failed, scanning with existing DB".
- Timings are also stored in MongoDB so health can be computed later.
- Prometheus metrics: scans total (by result), cache hits, queue depth, scan duration, DB age, last upstream check age, pre-check failures per source.

## 13. Acceptance criteria

1. `POST /api/v2/scans` for a new image returns 202; the state API goes `queued` -> `scanning` -> `done` with a stored result and recorded timings.
2. Same digest again with an unchanged DB returns 200 with `cached: true` and **no Trivy process is started**.
3. After the DB updates, the same digest is scanned again.
4. `force: true` always scans.
5. A new tag pointing to an already-scanned digest is a cache hit.
6. Unknown `scan_id` returns `not_found` (404).
7. With the mirror blackholed, the pre-check fails within its timeout (no long hang), the next fallback source is tried, and if all fail the scan proceeds with the old DB and responses say `stale`.
8. Pre-check logs show source, route (direct/proxy/SOCKS5), TLS and HTTP/2 results, and no secrets.
9. `GET /api/v2/health` reflects Mongo, DB age, queue and recent scan stats; readiness is false when Mongo is down.
10. New platforms appear in the `platforms` collection on first discovery.
11. Harbor adapter endpoints still pass their existing tests. Adapter output matches upstream except one documented addition: every vulnerability's `vendor_attributes` carries `Trivy: { Target, Type }` (the Trivy result target and type).
12. A request with `platforms: ["npm"]` returns only npm findings, sets `has_more_platforms` when the image has other platform types, and still records those other types in the `platforms` collection.
13. A request with a broader scope than the cached scan (extra platform or lower severity) triggers a new scan.
14. Trivy never downloads a DB during a scan; all DB downloads go through our own module.

## 14. Deferred ideas and open questions

### Deferred (not in v1)

1. **Digest store**: a separate `digests` collection keyed by image digest. **Declined by the owner for now because it is hard to implement.** v1 finds the last scan of a digest through the `scans` collection (index on `image.digest`). The idea is saved for later, since layers are often shared across images and this lookup may become a bottleneck:

```json
{
  "_id": "sha256:...",
  "first_seen_at": "",
  "seen_as": [ { "repository": "", "name": "", "tag": "" } ],
  "layers": [],
  "last_scan": { "scan_id": "", "db_updated_at": "", "platforms": [], "severity": [], "finished_at": "" },
  "platforms": []
}
```

2. **Multi-architecture images**: an image index has several manifests with different digests, so the cache key depends on which one is scanned. To decide together with the digest store.
3. **Queue priorities**: to be decided after R&D on Trivy's behaviour (CPU, memory, duration per image size). The `priority` field is reserved.
4. **Retention**: how long old scans stay in MongoDB.

### Open questions

None blocking. Next step is the implementation plan.
