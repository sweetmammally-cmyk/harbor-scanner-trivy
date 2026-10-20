# DEMAND: Direct Scan API, Scan Cache and DB Lifecycle for harbor-scanner-trivy

Status: DRAFT v0.22 (seed DB build option, deferred resume, 2026-10-20)
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
| MongoDB | Hard dependency. If it is down, the service is not ready and the API returns 503. The DB updater keeps running while MongoDB is down: its state stays in memory and is written to MongoDB when it is reachable again. |
| Cache key | Image digest (not tag). Layers are often shared across images. |
| Stored scans | Current state only: one document per image tag (`_id` = scan_id = sha256 of `<repository>/<name>:<tag>`). A new scan of the tag overwrites the previous result; there is no history. |
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

### 5.0 Common rules

- `/api/v2/` is routed only when `SCANNER_V2_API_ENABLED` is true; with v2 disabled nothing changes. `/probe/*` stays unauthenticated; every `/api/v2/...` endpoint, including `/api/v2/health` and `/api/v2/db`, requires the token.
- Auth: `Authorization: Bearer <token>`, compared in constant time on the SHA-256 hashes. One token, `SCANNER_V2_AUTH_TOKEN`, at least 32 characters; startup fails when v2 is enabled and it is missing or shorter. A missing or wrong token gives 401 `unauthorized` with `WWW-Authenticate: Bearer`. Tokens are never logged. This is caller authentication only; registry access uses the robot account.
- HTTP hygiene: request bodies at most 1 MiB (413 `invalid_request` above); `Content-Type: application/json` required on bodies (415 `invalid_request` otherwise); strict JSON decoding (unknown fields or trailing data give 400 `invalid_request`); the server's read, header, write and idle timeouts are set (`SCANNER_API_SERVER_*`; the header timeout is the read timeout; a POST extends its own write deadline to cover the synchronous digest resolution). At most `SCANNER_V2_MAX_INFLIGHT` (default 32) POSTs run at once; beyond it 429 `too_many_requests` with `Retry-After: 1`.
- One log line per request: method, route template, status, duration and request id; never bodies or headers. `X-Request-ID` is accepted when it is 1-128 characters of `A-Za-z0-9._:-`, otherwise generated, and returned in the response.
- One error shape: `{"error": {"code": "...", "message": "..."}}`. Codes: `invalid_request` (400/413/415), `unauthorized` (401), `image_not_found` (404), `registry_auth_failed` (502), `registry_unavailable` (503, `Retry-After`), `queue_full` (429, `Retry-After`; only for a full queue), `too_many_requests` (429, `Retry-After: 1`; the in-flight cap), `scan_in_progress` (409, `Retry-After: 5`), `not_ready` (503: schema not ready or no DB installed), `store_unavailable` (503: MongoDB down or a MongoDB call failed), `internal` (500). Messages never contain secrets, paths or stderr.
- Not found: `GET /api/v2/scans/{scan_id}` answers 404 with `{"scan_id": "...", "state": "not_found"}`.

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

Fields (anything else is 400):

- `request_id`: optional correlation id, 1-128 characters of `A-Za-z0-9._:-`; stored as `last_request_id` and logged. Not unique and not an idempotency key: the document identity (one document per tag) is the idempotency, so a Temporal retry finds the same document.
- `requested_at`: optional, RFC 3339, at most 5 minutes in the future. Audit only; the server also stores `received_at`.
- `image`: `repository`, `name` and `tag` follow the OCI distribution rules (section 6.1); otherwise 400. The tag is resolved to a digest synchronously in this request.
- `customer_ids`: required, 1-100 entries of 1-128 characters.
- `customer_data`: optional JSON object of at most 64 KiB (JSON-encoded).
- `platforms`: required, 1-20 Trivy result types (npm, jar, pip, ...); lowercased, deduplicated and sorted.
- `severity`: optional, from CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN (uppercased, deduplicated, sorted); default `["CRITICAL","HIGH"]`.
- `max_db_age`: optional duration (our parser, so `1d` works), between 1m and 30d; default `SCANNER_DB_MAX_AGE_DEFAULT`. How fresh the DB must be for `freshness: ok` (section 7.4).
- `force`: always scan, ignore the cache.

The `scan_id` is the lowercase hex sha256 of `"<repository>/<name>:<tag>"`: the id of the tag's document.

Order: auth -> body size, decoding and validation (400) -> not ready (503: MongoDB down, schema not ready, no DB installed) -> resolve the digest (synchronous, section 6.1 error mapping) -> active-scan check -> cache decision (section 6) -> enqueue (section 9). There is no separate idempotency step.

| Case | HTTP | Body |
|---|---|---|
| New scan queued | 202 | `{ "scan_id", "state": "queued", "db" }` |
| The tag is queued/scanning for the same digest and the running scope covers the request (also with `force: true`; the document is not changed) | 200 | `{ "scan_id", "state", "db" }` |
| The tag is queued/scanning for another digest, or for a scope that does not cover the request | 409 | `scan_in_progress`, `Retry-After: 5` |
| Cache hit (section 6) | 200 | the result view (5.2) with `"cached": true, "db_unchanged": true` |
| Queue full | 429 | `queue_full`, `Retry-After` |
| Too many POSTs in flight | 429 | `too_many_requests`, `Retry-After: 1` |
| MongoDB unavailable / not ready | 503 | `store_unavailable` / `not_ready` |

`cached` and `db_unchanged` appear only in POST hit responses; they are never stored.

Every response with a DB section carries:

```json
"db": { "updated_at": "...", "last_upstream_check_at": "...", "confirmed_at": "...", "freshness": "ok|stale" }
```

`updated_at`, `confirmed_at` and `freshness` are the values stored on the document (section 10): set when a scan completes (the DB captured at scan start, freshness against that request's `max_db_age`) and renewed by every hit. Nothing is recomputed on read. `last_upstream_check_at` is this instance's. While a tag has no result yet, the block shows the current local DB state.

### 5.2 Scan state: `GET /api/v2/scans/{scan_id}`

| `state` | HTTP | Meaning for the caller |
|---|---|---|
| `not_found` | 404 | Not here, or the id is not 64 lowercase hex characters. Submit again. |
| `queued` | 200 | Waiting in the queue. `Retry-After: 2`. |
| `scanning` | 200 | Trivy is running. `Retry-After: 2`. |
| `done` | 200 | Finished. The result view is included. |
| `failed` | 200 | Finished with an error: `error` has the failure class and a short fixed message (never the stored detail). |

The state describes the tag's current attempt. Findings are returned only when the state is `done`. For `queued`, `scanning` and `failed`, a `previous` block `{confirmed_at, digest, summary}` is included when the tag has a last good result.

Optional query parameters `platforms` and `severity` (comma-separated, same rules as POST) filter the view; the default view is the full stored scope. A filter outside the stored scope is 400.

The result view (GET `done` and POST hits) is filtered to the request:

```json
{
  "scan_id": "...", "state": "done",
  "cached": true, "db_unchanged": true,
  "image": { "repository": "", "name": "", "tag": "", "digest": "sha256:..." },
  "db": { "updated_at": "", "last_upstream_check_at": "", "confirmed_at": "", "freshness": "ok" },
  "platforms_requested": ["npm"], "platforms_found": ["npm"], "platforms_not_found": [],
  "has_more_platforms": true,
  "severity": ["CRITICAL", "HIGH"],
  "summary": { "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0 },
  "truncated": false,
  "vulnerabilities": [],
  "timing": { "queue_wait_ms": 0, "scan_ms": 0, "total_ms": 0 }
}
```

- `vulnerabilities`: the stored findings of the requested platforms and severities.
- `summary`: summed from `summary_by_platform` over the requested platforms only, at every severity.
- `platforms_found`, `platforms_not_found` and `has_more_platforms` are computed for the request from `image_platform_types`.
- `image.digest` is the digest of the result.

### 5.3 Query scans: `GET /api/v2/scans`

- Filters: `customer_id`, `digest` (matches `result.digest` or `image.digest`), `repository`, `name`, `state`, `platform` (a type found in the image: `result.image_platform_types`), `request_id` (`last_request_id`), `from` and `to` (RFC 3339, on `created_at`).
- Order: `created_at` descending, then `_id` descending; `created_at` is set once when the tag's document is created and never changes.
- Keyset pagination (no skip): `limit` default 50, at most 200; the response has `items` and an opaque `next_cursor` (absent on the last page), passed back as `cursor`.
- Items never contain findings or the report (projection).

This is the filtering Harbor cannot do.

### 5.4 DB status: `GET /api/v2/db`

- This instance, per DB kind (`db`, `java-db`), from its in-memory state, so it works while MongoDB is down: version, `updated_at`, `downloaded_at`, `installed_at`, manifest digest, `last_upstream_check_at`, `last_confirmed_current_at`, `newer_available`, mode (`normal` | `degraded`), `db_age`, freshness against `SCANNER_DB_MAX_AGE_DEFAULT`, the last per-source results (credentials in source URLs redacted).
- Other instances' states from MongoDB, best effort (left out with a note while MongoDB is down).

### 5.5 Health

- Liveness (`/probe/healthy`) stays trivial: the process answers. It never depends on MongoDB or the DB.
- Readiness (`/probe/ready`), when v2 is enabled, is false while: MongoDB is down, the schema is not ready, no Trivy DB is installed, the trivy binary is missing, the service is shutting down, or a Java DB is required (`SCANNER_JAVA_DB_SOURCES` set) but missing. Degraded DB mode does not make it unready. MongoDB state comes from the background ping flag, never a direct MongoDB call. With v2 disabled the v1 probes are unchanged.
- `GET /api/v2/health` (token required): `status` `ok` | `degraded` | `unhealthy`; HTTP 200 for ok and degraded, 503 for unhealthy.
  - unhealthy: any readiness condition above, or no worker running.
  - degraded: any DB kind in degraded mode or with `newer_available`; freshness `stale` (against `SCANNER_DB_MAX_AGE_DEFAULT`); a DB older than `SCANNER_DB_AGE_WARN`; the oldest queued scan older than `SCANNER_HEALTH_QUEUE_STUCK_AFTER` (default 10m) while workers run; more than 50% failures in the last 20 scans of this replica (at least 10 samples; in-memory window).
  - Body: each check with its status and a short sanitized detail; this instance's DB states; queue depth and oldest queued age; recent-scan counts; every instance's DB state with its last-updated time (best effort from MongoDB). Never secrets, paths or stderr.

### 5.6 Startup and shutdown

- Startup (v2 enabled): store client and its monitor (schema ensured when MongoDB is up) -> DB updater -> workers and reaper -> HTTP server.
- Shutdown (SIGTERM): v2 readiness false (new POSTs get 503) -> HTTP server shutdown (in-flight requests drain) -> workers stop claiming, running scans get `SCANNER_SHUTDOWN_GRACE`, then they are killed and released -> updater stops -> MongoDB connection closed.

## 6. Scan flow and cache rules

```
POST /api/v2/scans (order in 5.1)
  -> active scan on this tag (queued/scanning):
       same digest and the running scope covers the request -> 200 with its state
       otherwise -> 409 scan_in_progress
  -> cache hit on this tag's document if ALL are true:
       - force == false
       - no active scan
       - result.digest == the resolved digest
       - same scanned platform (`SCANNER_SCAN_PLATFORM`) and same Trivy version
       - the stored platforms and severities cover the request (superset)
       - result db.updated_at >= the installed DB's UpdatedAt
     => the hit renews the document: confirmed_at = now, db.freshness recomputed
        against THIS request's max_db_age, customer_ids, customer_data and
        last_request_id overwritten, state done. No new document.
        200 with the filtered view, cached: true, db_unchanged: true
  -> else: ANOTHER document with result.digest == the resolved digest that meets
     the same result conditions (it may be queued or scanning: its result is
     still valid) => its result is copied into this tag's document, with its
     GridFS content copied to a new file for this tag; respond as a hit. If the
     source file is gone (overwritten in between), the lookup is done once more,
     then it is a miss. Copies are independent.
  -> else: enqueue (section 9) => 202 (or 429)
worker:
  -> log "triggering scan"
  -> run Trivy with the local DB (no network DB update during scan)
  -> store result, upsert discovered platforms
  -> log "scan done, took X ms"
```

Notes:

- `requested_at` is stored for audit only. It is not used to decide whether to skip.
- Trivy already caches per-layer analysis (by layer ID) so shared layers are cheap to re-analyze. Vulnerability matching still runs against the DB on each scan. The digest cache adds whole-image skipping on top.
- Every result stores the DB `UpdatedAt` it used. Validity is decided by the DB version rule, never by time.
- A request for a narrower scope is served from a wider stored result (filtered view). A broader scope (more platforms or a severity that was not stored) is a cache miss and triggers a new scan, because those details were never stored. For the same digest the scope only widens: the new scan covers the union of the stored and the requested platforms and severities. If the tag moved to another digest, the scope is just the request's.
- Trivy runs once per scan. Summary counts are kept for all severities of the scanned platforms; details only for the scanned severities. Only the scanned result types are persisted; Trivy's full output is not stored.

## 7. Trivy DB lifecycle

### 6.1 Resolving the digest (registry client)

- The registry client reuses the OCI client of the DB download (section 7.5) and its token flow: the robot account's basic credentials go to the token endpoint, scope `repository:<repo>:pull`; tokens are cached until they expire, fetched once per scope at a time (single-flight), and an endless chain of auth challenges is cut off after a few attempts.
- `HEAD` on the manifest with `Accept`: OCI image index, Docker manifest list, OCI image manifest, Docker v2 manifest. The digest is `Docker-Content-Digest`; if that header is missing, the manifest is fetched with `GET` and the digest is the sha256 of the exact bytes. The manifest `media_type` is stored with the scan (multi-architecture handling stays deferred, section 14).
- The scan runner scans `registry/repository/name@digest`, never the tag.
- `SCANNER_REGISTRY_TIMEOUT` (default 15s) per request; one retry with a short backoff on network errors and 5xx; no retry on 401, 403 or 404.
- Errors: 404 -> `image_not_found` (HTTP 404); 401/403 -> `registry_auth_failed` (HTTP 502); timeout or 5xx -> `registry_unavailable` (HTTP 503 with a retry hint).
- `http://` registry URLs are allowed, with one WARN at startup. Credentials and tokens are never logged.

### 6.2 Scan runner (Trivy)

- The target Trivy version is the one pinned in the Dockerfile (0.74.0).
- Trivy runs once per scan on `registry/repository/name@digest` with `image --scanners vuln --format json --output <file> --list-all-pkgs=false --skip-db-update --skip-java-db-update --skip-version-check --image-src remote --cache-dir <worker dir> --timeout <slightly below SCANNER_SCAN_TIMEOUT>`, `--platform <SCANNER_SCAN_PLATFORM>` (default `linux/amd64`), and `--insecure` for an `http://` registry. The platform is stored as the result's `scanned_platform` and is part of the cache conditions; an image with no manifest for that platform fails with `platform_not_found`. Full multi-architecture handling stays deferred (section 14). No `--severity` flag: Trivy reports every severity and we filter. `--image-src remote` makes Trivy pull from the registry, never from a local Docker daemon; `--skip-version-check` makes no other network call.
- The child environment comes from an allowlist (`PATH`, `HOME`, `TMPDIR`, `TRIVY_*`, proxy variables), never the full environment. Registry credentials go in `TRIVY_USERNAME` / `TRIVY_PASSWORD`, never on the command line.
- Each worker has its own Trivy cache directory. At scan start its `db` (and `java-db`) symlink points at the concrete version directory of the installed DB; that version's `UpdatedAt` and manifest digest are stored with the scan, and the version is pinned while the scan runs (pruning skips pinned versions).
- The JSON goes to a private (0600) temporary file, which is stream-parsed and then deleted. Output above `SCANNER_SCAN_MAX_OUTPUT` fails the scan. Only the last 8 KiB of stderr is kept, redacted.
- Failure classes: `trivy_timeout`, `trivy_exit_error`, `output_too_large`, `output_invalid`, `db_missing` (no vulnerability DB installed; Trivy is not started), `java_db_missing` (the image has `.jar` files and no Java DB is installed: Trivy stops with "Unable to initialize the Java DB"; Trivy has no clean way to skip jar analysis, so this is a clear failure), `platform_not_found`.
- Requested platforms are matched against the result `Type`, case-insensitively. Platform strings: lowercase letters, digits, `-` and `_`, with a maximum count; severities: uppercase, from the fixed set UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL. Counts cover all severities of the requested platforms; details only the requested severities. All result types of the image are stored as `image_platform_types`, with the counts per scanned platform in `summary_by_platform`; responses derive `platforms_requested`, `platforms_found`, `platforms_not_found` and `has_more_platforms` (true when the image has other types) for the request. A requested platform that is not in the image must never look like a clean result. Every type found is upserted into `platforms`.
- A stored finding has: id, package, installed version, fixed version, severity, title, primary URL, status, target, type. Descriptions, references and package lists are dropped. At most `SCANNER_SCAN_MAX_FINDINGS` are stored, with `truncated: true` beyond it.
- Logging: "triggering scan" (scan_id, digest, customer ids, platforms, severities, Trivy version, db_updated_at) and "scan done" (durations, counts); findings are never logged. `trivy --version` runs at startup; the version is stored with each scan; readiness is false while the Trivy binary is missing.
- Measured with Trivy 0.71.2 and 0.74.0 (see PROGRESS): a result type with no findings still appears in the output with `--list-all-pkgs=false` (checked for an OS type and a language type), so package lists are not needed to discover types.

### 7.1 Always have a DB

- DB lives on a persistent volume; a seed DB is baked into the image so a fresh pod can start.
- DB updates are atomic: download to a temp directory, verify, then swap. Scans in flight keep using the previous copy. No scan ever sees a half-written DB.
- Readiness is false until a DB exists.

### 7.2 Update interval

- `SCANNER_DB_CHECK_INTERVAL` (e.g. `1h`, `3h`, `1d`). The `d` suffix must be supported.
- If unset or invalid, the **fallback interval is 3h** and, when v2 is enabled, a WARN log says "using fallback interval".
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
- A download that fails because the HTTP/2 stream was reset (`RST_STREAM`, for example by a proxy or CDN after minutes of transfer) fails that source with class `stream_reset` (in the logs, `db_checks` and the failure metric); other download failures are `download_error`. There is no resume: the next source is tried, and the next run starts the download again.
- A write error on our own disk during install (for example a full disk) fails that source with class `install_error`, leaves no partial directory and keeps the old DB; when no other source installs, the result is `degraded` with `newer_available`. There is no free-space check before downloading.
- No source answered: log ERROR once, set mode `degraded`, keep scanning with the existing DB, keep retrying until fixed.
- A newer DB was offered but none could be installed: set mode `degraded` and `newer_available`, log ONE ERROR "newer DB available but could not be installed" with each source's failure class, keep scanning with the existing DB. Responses say `stale`.
- `db.freshness` in responses: `stale` while `newer_available` is set, regardless of `max_db_age`. Otherwise `ok` if the DB was confirmed current within `max_db_age`, measured from `last_confirmed_current_at` (not from `UpdatedAt`, because upstream may simply not have published a newer DB). "Upstream" here means the first source that answered. Otherwise `stale`.
- DB age (now minus the installed DB's `metadata.json` `UpdatedAt`) is reported separately as `db_age` in `GET /api/v2/db` and in the health output. After each check, when the age is above `SCANNER_DB_AGE_WARN`, a WARN log gives the age and the active source. This is for visibility only and never blocks an install.
- On-demand refresh, when a request's `max_db_age` is exceeded (freshness `stale` for that request):
  - It runs in the scan worker before the scan, not in the HTTP handler.
  - It joins or starts one update run (single-flight) and waits at most `SCANNER_ONDEMAND_REFRESH_WAIT` (default 60s). On timeout or failure the scan proceeds with the old DB and the response says `stale`; the update run continues in the background.
  - If an update run finished within `SCANNER_ONDEMAND_REFRESH_MIN_GAP` (default 60s), its result is reused and no new run is started.
  - If the mode is `degraded`, no on-demand refresh is started; the retry interval governs and freshness stays `stale`.
- The installed DB's manifest digest is stored on disk with the DB (a `manifest-digest` file in its version directory), so the upstream check after a restart does not depend on stored state.

Java DB has its own optional source list (`SCANNER_JAVA_DB_SOURCES`, same format) and follows the same pre-check and fallback flow. Without Java sources there is no Java DB at all, not even the seed.

### 7.5 Own DB download module

- The scanner downloads the Trivy DB itself as an OCI artifact (manifest, then the DB layer, which is extracted to Trivy's DB directory with `trivy.db` and `metadata.json`).
- Because we own the download path, the same route (direct, HTTP proxy, SOCKS5) is used for pre-checks and for the download. There is no second code path that can behave differently.
- The OCI client shared with the registry client sends each request without a token first and answers the 401 challenge with a cached token: one extra round trip per request (no extra token fetch). This is a known, accepted cost.
- Trivy is then run with its own DB update disabled, so it never tries to download anything during a scan.
- The module verifies content digests, writes to a temp directory and swaps atomically (see 7.1).

## 8. Platforms

- A platform is a Trivy result type (npm, jar, pip, and so on, including OS types such as debian or alpine).
- The request lists the platforms to scan and report on. Only findings of those platforms (at the requested severities) are stored as details and returned. For example, a request for `["npm"]` does not return base-image OS findings.
- Each result lists the `platforms` that were reported and a flag `has_more_platforms`: true when the image contains other platform types than the ones requested.
- A separate `platforms` collection is upserted whenever a platform type is discovered in any scan, requested or not, so the full set is visible at a glance (first seen, last seen, count, example digest).

## 9. Queue

- The queue is the `scans` collection: each scan document is its job. No multi-document transactions. Requires MongoDB 4.2 or newer (pipeline updates and `$$NOW`).
- Claim: `findOneAndUpdate` on `state: queued`, oldest `queued_at` first, setting `state: scanning`, `worker`, `lease_until` and `attempt + 1`. All lease times use MongoDB's clock (`$$NOW` in pipeline updates and `$expr` comparisons), never a replica's clock.
- Lease `SCANNER_QUEUE_LEASE` (60s), heartbeat every third of it (20s). Every worker write (heartbeat, completion) is conditional on `_id` + `worker` + `attempt`; no match means the lease was lost: the result is discarded and the Trivy process group is killed.
- Reaper on every replica every 30s: an expired `scanning` scan goes back to `queued`; after `SCANNER_QUEUE_MAX_ATTEMPTS` (3) it becomes `failed` with class `worker_lost`. Only lease loss is retried automatically.
- One document per image tag (section 10). Enqueue: the first scan of a tag inserts the document (a duplicate key means another request created it: read it and decide again). Later scans update the document, only while its state is not `queued` or `scanning`: state `queued`, `queued_at`, `attempt` 0, the new options and request fields. The previous result stays until the new scan succeeds.
- While the tag is `queued` or `scanning`: a request for the same digest whose platforms and severities are covered by the running scan's scope gets 200 with that state; any other request gets 409 `scan_in_progress` with `Retry-After`.
- Scope widening (section 6): for the same digest the new scan covers the union of the stored result's and the requested platforms and severities.
- A successful scan replaces the result fields (`result`, `db`, `confirmed_at`) and deletes the previous GridFS file of the document (best effort, after the new document is saved). A failed scan sets state `failed` with its class and a sanitized message and leaves the last good result in place.
- Leases, fencing, the reaper, release and shutdown apply to the tag's document as described here.
- Queue full: `queued` count >= `SCANNER_QUEUE_MAX_LENGTH` gives 429 with `Retry-After`.
- Workers poll every `SCANNER_QUEUE_POLL_INTERVAL` (2s, with jitter) and are woken at once by an enqueue in the same process. No change streams.
- Workers do not claim while MongoDB is not ready or no DB is installed. Before each scan they call the on-demand DB refresh (7.4).
- Shutdown (SIGTERM): stop claiming, wait up to `SCANNER_SHUTDOWN_GRACE` (30s), then kill the running scans and release their leases at once (back to `queued`, `attempt` not counted). The container's stop grace period (compose `stop_grace_period`) must be longer.
- A completion write is retried with backoff for up to 2 minutes; then an ERROR log with the `scan_id`, and the reaper requeues the scan.
- Metrics: queue depth, oldest queued age, claim latency, lease losses, reaper requeues.
- Priority levels are deferred: the owner will study Trivy's behaviour first (R&D). The schema reserves an optional `priority` field so adding it later is not a migration.

## 10. Data plane (MongoDB, draft)

`scans` (also acts as the job record)

One document per image tag, current state only. `_id` is the scan_id: lowercase hex sha256 of `"<repository>/<name>:<tag>"`.

```json
{
  "_id": "scan_id", "created_at": "", "last_request_id": "", "requested_at": "", "received_at": "",
  "customer_ids": [], "customer_data": {},
  "image": { "repository": "", "name": "", "tag": "", "digest": "", "media_type": "" },
  "options": { "platforms": ["npm"], "severity": ["HIGH","CRITICAL"], "max_db_age": 0 },
  "reference": "registry/repository/name@digest",
  "state": "queued|scanning|done|failed",
  "queued_at": "", "started_at": "", "finished_at": "",
  "queue_wait_ms": 0, "scan_ms": 0, "total_ms": 0,
  "worker": "", "lease_until": "", "attempt": 0, "priority": null,
  "error": "", "failure_class": "",
  "result": {
    "digest": "", "platforms": [], "severity": [],
    "scanned_platform": "linux/amd64", "trivy_version": "",
    "image_platform_types": [], "summary": {}, "summary_by_platform": {},
    "truncated": false, "report": { "findings": [] }, "report_gridfs_id": null
  },
  "db": { "updated_at": "", "manifest_digest": "", "freshness": "ok|stale" },
  "confirmed_at": ""
}
```

- `image`, `options`, `reference`, `state`, the timings and the queue fields describe the current attempt; `image.digest` is the digest resolved by the last enqueue.
- `result`, `db` and `confirmed_at` describe the last successful scan and are replaced only when a new scan succeeds (or renewed by a cache hit). `result.digest` is the digest that was scanned. `db.updated_at` is the DB the findings come from (captured at scan start); `db.freshness` is computed against the max_db_age of the request that produced or renewed the result.
- `customer_ids`, `customer_data`, `last_request_id`, `requested_at` and `received_at` are those of the last request (enqueue or cache hit). `created_at` is set when the document is created and never changes (list order).

`platforms`: `{ _id, first_seen_at, last_seen_at, seen_count, example_digest }`

`db_state`: one document per scanner instance and DB kind, `_id` `"<instance_id>:<kind>"` (kind `db` or `java-db`), with `instance_id`, `db`, mode, active source, manifest digest, `last_upstream_check_at`, `last_confirmed_current_at`, `newer_available`, `installed_at`, metadata (version, `updated_at`, `next_update`, `downloaded_at`) and the last per-source results. The instance id is `SCANNER_INSTANCE_ID` (default: the hostname). Behaviour: the state is kept in memory first; while MongoDB is down the updater keeps running and the state is written when MongoDB is back (also without a new update run); at startup the instance loads its stored state, but if the stored digest differs from the digest installed on disk, the stored confirmation (`last_confirmed_current_at`, `newer_available`) is ignored: the disk is the source of truth. On the first time MongoDB becomes ready after boot: if no update run has completed since startup, the stored state is loaded first (with the disk check) and nothing older is overwritten; if a run has completed, the memory state is written. Each document has `updated_at` (set on every write) and a TTL index on it from `SCANNER_DB_STATE_RETENTION`, so states of instances that are gone expire.

`db_checks`: history of pre-checks and downloads (`instance_id`, db, source, route, per-stage timings, result, at). Each row has a deterministic `_id` `"<instance_id>:<kind>:<run_started_at>:<source>"` and is written with an upsert, so a repeated flush never duplicates rows. TTL index to expire old rows. Best effort: while MongoDB is down they are buffered in memory with a bound; when the buffer is full the oldest are dropped and the number dropped is logged.

Schema setup ("ensure schema"):

- Runs at startup when MongoDB is up, and again every time the MongoDB up flag goes from false to true; it is retried until it succeeds. Readiness requires "schema ready" in addition to MongoDB being up.
- `createIndexes` is the only index mechanism (idempotent, safe with several replicas starting at once). Indexes are never dropped or recreated automatically: an existing index with the same name or keys but different options logs an ERROR naming the index, and the replica stays not ready.
- A `schema_version` document is created with an upsert and `$setOnInsert`, so concurrent replicas cannot collide. If the stored version is higher than the code's, the replica stays not ready with a clear ERROR. If it is lower, migrations run (none yet) and the version is then set.

Indexes:

- `scans(result.digest)` (cache copy lookup and the digest filter), `scans(image.digest)`, `scans(customer_ids, created_at desc, _id desc)`, `scans(created_at desc, _id desc)` (the list order), `scans(state, queued_at)` (queue claim and the state filter), `scans(state, lease_until)` (reaper). There is no unique index besides `_id` (schema version 4; nothing was deployed before it, so older development databases are recreated instead of migrated).
- `db_checks.at`: TTL index (`at` is a BSON date), `expireAfterSeconds` from `SCANNER_DB_CHECKS_RETENTION`. When the retention changes, the index is updated with `collMod`, never dropped.

Large reports: summary plus report inline; the full report moves to GridFS when its BSON-encoded size is above 8 MiB (a code constant; the BSON document limit is 16 MiB). The GridFS file is uploaded first (metadata `scan_id`, `uploaded_at`), then the scan document is saved; if that save fails, the new file is deleted at once (best effort) and the previous result keeps its file. After a successful save, the document's other files (the previous result's) are deleted (best effort). List queries (`GET /api/v2/scans`) never return the report (projection). Cleanup of old files is part of retention (section 14).

## 11. Configuration (draft)

| Variable | Purpose |
|---|---|
| `SCANNER_V2_API_ENABLED` | Feature flag for the new API |
| `SCANNER_V2_AUTH_TOKEN` | Service token for the new API (secret). One token, compared in constant time, at least 32 characters; startup fails when v2 is enabled and it is missing or shorter |
| `SCANNER_V2_MAX_INFLIGHT` | Most POSTs handled at once; beyond it 429. Default 32 |
| `SCANNER_V2_CACHE_DIR` | Directory of the v2 DBs (version directories), the per-worker Trivy layer caches and the per-scan temp directories, separate from the Harbor adapter's `SCANNER_TRIVY_CACHE_DIR`. Default `/home/scanner/.cache/scanner-v2`. A persistent local SSD volume, not network storage; no tmpfs anywhere (the OS page cache keeps the DB in RAM when memory is free). Each scan gets its own temp directory inside it (Trivy's `TMPDIR` and the output file), removed when the scan ends (success, failure, timeout or kill); leftovers are removed at startup. There is no separate temp-dir setting |
| `SCANNER_V2_WORKER_CACHE_BACKEND` | Trivy layer cache of the workers: `fs` (default; a `fanal` cache per worker on disk, reused across scans) or `memory` (Trivy's in-memory cache: nothing of the layer cache is written to disk, and it lives for one scan only, since each scan is one Trivy process) |
| `SCANNER_V2_WORKER_CACHE_MAX` | `fs` backend only: between scans, a worker whose layer cache is larger than this clears its own layer cache (never the DB). Default 5GB per worker |
| `SCANNER_MONGO_URI`, `SCANNER_MONGO_DB` | MongoDB. Required, no defaults. If the v2 API is enabled and either is missing, startup fails with a clear error (config error). If MongoDB is only unreachable, the service does not exit: it keeps running with readiness false and the v2 API returning 503, the DB updater keeps running, and the driver reconnects automatically (no custom backoff loop). Write and read concern come from the connection string (no separate settings). The connection string is never logged or included in errors. No multi-document transactions are used. |
| `SCANNER_INSTANCE_ID` | Id of this scanner instance for `db_state` and `db_checks`. Default: the hostname, with a WARN at startup when v2 is enabled (set it explicitly, for example in compose) |
| `SCANNER_DB_STATE_RETENTION` | How long a `db_state` document lives after its last write (TTL index on `updated_at`, updated with `collMod`). Default 7d; startup fails if it is shorter than twice `SCANNER_DB_CHECK_INTERVAL` |
| `SCANNER_MONGO_CONNECT_TIMEOUT` | Connect timeout. Default 5s |
| `SCANNER_DB_CHECKS_RETENTION` | How long `db_checks` documents are kept (TTL index). Default 30d (the `d` suffix is supported) |
| `SCANNER_MONGO_SERVER_SELECTION_TIMEOUT` | Server selection timeout. Default 5s |
| `SCANNER_MONGO_OPERATION_TIMEOUT` | Deadline of every MongoDB call. Default 10s |
| `SCANNER_REGISTRY_URL` | Harbor URL used to resolve digests and pull images. `http://` is allowed (one WARN at startup) |
| `SCANNER_REGISTRY_TIMEOUT` | Timeout of each registry request. Default 15s |
| `SCANNER_REGISTRY_USERNAME`, `SCANNER_REGISTRY_PASSWORD` | Robot account (secret). Harbor robot names contain `$`, which needs escaping in compose files and shells |
| `SCANNER_DB_CHECK_INTERVAL` | `1h`, `3h`, `1d`... fallback `3h` |
| `SCANNER_DB_SOURCES` | Required when the v2 API is enabled (startup fails if empty). The same repository and route listed twice is a startup error (also in `SCANNER_JAVA_DB_SOURCES`). Ordered pool of sources: `repo\|route[\|options],...`, route is `direct`, `http://host:port` or `socks5://host:port`; options is an optional `;`-separated list, today only `allow-http1` (pass the pre-check over HTTP/1.1). Recommended order for both DBs: our own mirror first, Docker Hub (`docker.io/aquasec/trivy-db:2`, `docker.io/aquasec/trivy-java-db:1`) as the fallback; ghcr.io is not used. Example: `mirror.local/aquasecurity/trivy-db:2\|direct,docker.io/aquasec/trivy-db:2\|direct` |
| `SCANNER_JAVA_DB_SOURCES` | Optional, same format, for the Java DB. Empty means no Java DB at all: nothing is downloaded and the Java seed is not installed |
| `SCANNER_PRECHECK_TIMEOUT_DNS`, `_CONNECT`, `_TLS`, `_HTTP`, `_MANIFEST`, `_TOTAL` | Pre-check timeouts per stage and overall. Defaults 5s, 5s, 5s, 10s, 10s, 30s |
| `SCANNER_DB_SEED_DIR`, `SCANNER_JAVA_DB_SEED_DIR` | Seed DB in the image, installed when no DB exists yet (with no digest, so the first update downloads). Defaults `/home/scanner/seed/db` and `/home/scanner/seed/java-db`. A missing directory means no seed; the service is then not ready until the first download succeeds. The default image has no seed; the Dockerfile build argument `WITH_SEED_DB=true` bakes the Trivy DB seed in for offline installs |
| `SCANNER_DB_DOWNLOAD_STALL_TIMEOUT` | Abort a download when no bytes arrive for this long. Default 30s |
| `SCANNER_DB_DOWNLOAD_TIMEOUT` | Overall cap per source per download of the Trivy DB (safety net). Default 15m |
| `SCANNER_JAVA_DB_DOWNLOAD_TIMEOUT` | Same for the Java DB. Default 45m |
| `SCANNER_DB_RETRY_INTERVAL` | Check interval while the mode is `degraded`. Default 15m |
| `SCANNER_DB_AGE_WARN` | Log a WARN after a check when the installed DB's `UpdatedAt` is older than this. Visibility only. Default `7d` (the `d` suffix is supported) |
| `SCANNER_DB_MAX_AGE_DEFAULT` | Default for `max_db_age`. Default 6h |
| `SCANNER_ONDEMAND_REFRESH_WAIT` | How long a scan waits for an on-demand DB refresh before it proceeds with the old DB. Default 60s |
| `SCANNER_ONDEMAND_REFRESH_MIN_GAP` | An update run that finished within this gap is reused instead of starting an on-demand refresh. Default 60s |
| `SCANNER_QUEUE_WORKERS`, `SCANNER_QUEUE_MAX_LENGTH` | Queue settings. Defaults 1 and 100 |
| `SCANNER_QUEUE_LEASE` | Lease of a running scan; heartbeat every third of it. Default 60s |
| `SCANNER_QUEUE_MAX_ATTEMPTS` | Lease losses before a scan fails with `worker_lost`. Default 3 |
| `SCANNER_QUEUE_POLL_INTERVAL` | How often idle workers look for work (with jitter). Default 2s |
| `SCANNER_SHUTDOWN_GRACE` | How long running scans may finish after SIGTERM. Default 30s |
| `SCANNER_HEALTH_QUEUE_STUCK_AFTER` | Health is `degraded` when the oldest queued scan is older than this while workers run. Default 10m |
| `SCANNER_SCAN_PLATFORM` | Platform scanned in a multi-platform image (`--platform`). Default `linux/amd64` |
| `SCANNER_SCAN_TIMEOUT` | Per-scan timeout; Trivy gets a slightly shorter `--timeout`, then the whole process group is killed. Default 10m |
| `SCANNER_SCAN_MAX_OUTPUT` | Largest Trivy JSON output read; above it the scan fails with `output_too_large`. Default 256 MiB |
| `SCANNER_SCAN_MAX_FINDINGS` | Most findings stored per scan; above it the scan is marked `truncated: true` and the counts stay complete. Default 10000 |

All defaults can be overridden by env. Existing Trivy variables keep their current behavior.

## 12. Logging and observability

- Structured logs with `scan_id`, `digest`, `customer_ids`.
- Required lines: "triggering scan", "scan done" with duration, "scan skipped (db unchanged)", DB source selection, each pre-check stage result, "using fallback interval", "all DB sources failed, scanning with existing DB".
- Timings are also stored in MongoDB so health can be computed later.
- Every required line has a log-capture test, and a test checks that no secret appears in any log, metric or health body.
- Prometheus metrics on the adapter's existing `/metrics` (same listener, unauthenticated; the port must stay internal), prefix `scanner_v2_`: scans by result (`done`, `failed`, `hit`, `copy_hit`), scan duration and queue wait histograms, queue depth, oldest queued age, lease losses, reaper requeues, claim latency, `mongo_up` (from the ping flag), `db_age_seconds`, `db_confirmed_age_seconds`, `db_degraded`, `db_newer_available` (per DB kind), API requests by route template and status, in-flight requests, DB update runs and pre-check failures by class, build info (Trivy version, schema version). Labels never carry customer ids, digests, repositories or tags; a `source` label is the host only (no credentials); a `platform` label is one of Trivy's known types or `other`. Queue statistics are cached for 10s so a scrape does not query MongoDB each time.
- The adapter's "FULL TRIVY REPORT" debug log is removed (P10-5); all other v1 behaviour, including `vendor_attributes.Trivy`, stays.

## 13. Acceptance criteria

1. `POST /api/v2/scans` for a new image returns 202; the state API goes `queued` -> `scanning` -> `done` with a stored result and recorded timings.
2. Same digest again with an unchanged DB returns 200 with `cached: true` and **no Trivy process is started**.
3. After the DB updates, the same digest is scanned again.
4. `force: true` always scans.
5. A new tag pointing to an already-scanned digest is a cache hit: the result is copied into the new tag's document.
6. Unknown `scan_id` returns `not_found` (404).
7. With the mirror blackholed, the pre-check fails within its timeout (no long hang), the next fallback source is tried, and if all fail the scan proceeds with the old DB and responses say `stale`.
8. Pre-check logs show source, route (direct/proxy/SOCKS5), TLS and HTTP/2 results, and no secrets.
9. `GET /api/v2/health` reflects Mongo, DB age, queue and recent scan stats; readiness is false when Mongo is down.
10. New platforms appear in the `platforms` collection on first discovery.
11. Harbor adapter endpoints still pass their existing tests. Adapter output matches upstream except one documented addition: every vulnerability's `vendor_attributes` carries `Trivy: { Target, Type }` (the Trivy result target and type).
12. A request with `platforms: ["npm"]` returns only npm findings, sets `has_more_platforms` when the image has other platform types, and still records those other types in the `platforms` collection.
13. A request with a broader scope than the cached scan (extra platform or lower severity) triggers a new scan.
14. Trivy never downloads a DB during a scan; all DB downloads go through our own module.
15. A cache hit renews `confirmed_at` on the tag's document without creating a document.
16. A rescan of the same tag overwrites its result (one document per tag).
17. A request that is not covered by the tag's running scan returns 409 `scan_in_progress`.
18. For the same digest, the scope widens to the union of the stored and the requested platforms and severities.
19. A narrower request is served from a wider stored result, filtered to the request.

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
4. **Retention**: later, delete tag documents not confirmed for N days, with their GridFS file.
5. **Resume of DB downloads** (HTTP range requests after a reset): not now. Source fallback is the fix for transfers that get reset (`stream_reset`, section 7.4); the next run downloads again from the start.

### Open questions

None blocking. Next step is the implementation plan.
