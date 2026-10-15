# CHECKLIST

Legend: `[ ]` todo, `[~]` in progress (note where you stopped in PROGRESS.md), `[x]` done (tests passed).
Update this file after every task. Details: `PLAN.md`. Spec: `DEMAND.md`.

## Phase 0: Orientation and baseline
- [x] P0-1 Read repo; record package map, Go version, logger, config pattern, how Trivy is invoked, CI in PROGRESS "Repo facts"
- [x] P0-2 Run existing build and tests; record exact commands and baseline result
- [x] P0-3 Confirm or adjust the package layout (`pkg/v2/...`); record decision
- [x] P0-4 Decide Mongo test strategy and libraries (Mongo driver, SOCKS5); record decision
- [x] P0-5 Fill the Commands section of `CLAUDE.md`
- [x] P0-6 Make the baseline green (failing tests from commit `0c87038`, per the owner's `vendor_attributes.Trivy` decision); own commit, before P1-2

## Phase 1: Config and skeleton
- [x] P1-1 Feature flag `SCANNER_V2_API_ENABLED`; v2 wiring off by default
- [x] P1-2 Config struct and env parsing for all variables in DEMAND section 11
- [x] P1-3 Duration parser with `d` support; unset or invalid check interval falls back to 3h with a WARN log
- [x] P1-4 (follow-up: duplicate sources rejected) `SCANNER_DB_SOURCES` and `SCANNER_JAVA_DB_SOURCES` parser (ordered; route direct, HTTP proxy or SOCKS5), validation, redacted printing
- [x] P1-5 Unit tests for config

## Phase 2: DB pre-check module
- [x] P2-1 Route-aware dialer: direct, HTTP proxy (CONNECT), SOCKS5
- [x] P2-2 Stage runner with per-stage timeouts and an overall deadline; result struct (stage, ok, timing, detail)
- [x] P2-3 Stages in order: DNS, connect, TLS handshake (version, cipher, ALPN), HTTP/2 GET `/v2/`, DB manifest request. HTTP/2 required unless the source has `allow-http1`; always record the negotiated protocol
- [x] P2-4 `httptrace` timings: DNS, connect, TLS, first byte, total
- [x] P2-5 Log effective source, route and each stage result; redact credentials and Authorization
- [x] P2-6 Tests: ok server, blackhole (timeout), TLS failure, no HTTP/2, HTTP proxy, SOCKS5, redaction
- [x] P2-7 Manual debug entrypoint or test helper to run a pre-check against one source
- [x] P2-8 Classify pre-check failures (dns_failure, tcp_timeout, tcp_refused, tls_reset, tls_timeout, tls_alert, tls_cert_invalid with peer cert subject/issuer/expiry, plus http/manifest classes); record the class in the result and the log; tests with servers that reset, go silent, or send an alert after the ClientHello, and with an unknown-CA certificate

## Phase 3: DB download module
- [x] P3-1 OCI client over our transport (token auth if needed, manifest, blob); record raw-HTTP vs library decision
- [x] P3-2 Upstream check: compare remote manifest digest with the stored one
- [x] P3-3 Download DB layer only after the pre-check passed, with stall timeout and overall cap, verify digest, extract `trivy.db` and `metadata.json` to a temp dir
- [x] P3-4 Atomic swap; in-flight scans keep the old copy (record mechanism)
- [x] P3-5 Seed DB support; service not ready until a DB exists
- [x] P3-6 Source loop: pre-check, upstream check, download and install if the digest differs; stop on equal digest or install; failed sources recorded with class; no source answered = degraded, one ERROR log, old DB kept; return mode, active source and per-source results; `SCANNER_DB_AGE_WARN` WARN after each check; no downgrade guard
- [x] P3-7 Java DB through the same flow
- [x] P3-8 Parse `metadata.json` (UpdatedAt, NextUpdate, Version, DownloadedAt)
- [x] P3-9 Tests with a fake registry: success, wrong digest, truncated, hang mid-download, fallback to second source, all sources fail; plus a manual download of the real ghcr.io DB (about 70 MB) with duration, size and result recorded in PROGRESS
- [x] P3-10 ~~Free disk space check before each download~~ dropped by owner (reverted). Kept from this task: `SCANNER_JAVA_DB_DOWNLOAD_TIMEOUT` (45m) for the Java DB

## Phase 4: Updater and freshness
- [x] P4-1 Interval loop, first run at startup, single-flight; skip the Java DB when `SCANNER_JAVA_DB_SOURCES` is empty; `SCANNER_DB_RETRY_INTERVAL` (15m) while degraded, back to the check interval after a success
- [x] P4-2 State behind an interface: last_upstream_check_at, last_confirmed_current_at, newer_available (kept when no source answered), mode, active source (in-memory first)
- [x] P4-3 Freshness `ok|stale` from `last_confirmed_current_at` versus `max_db_age`; always `stale` while `newer_available`
- [x] P4-4 On-demand refresh for the scan worker when a request's `max_db_age` is exceeded: wait at most `SCANNER_ONDEMAND_REFRESH_WAIT` (60s), reuse a run that finished within `SCANNER_ONDEMAND_REFRESH_MIN_GAP` (60s), never while degraded
- [x] P4-5 Fake-clock tests (including the 3h fallback)

## Phase 5: MongoDB data plane
- [x] P5-1 Mongo client, connect, ping; hard-dependency behaviour (not ready, 503, no exit when unreachable); connect / server selection / operation timeouts; background ping every 5s sets the readiness flag; URI redaction test; integration tests: unreachable at startup, then comes back
- [x] P5-2 Models and collections: `scans`, `platforms`, `db_state`, `db_checks`
- [x] P5-3 Ensure schema on every Mongo up transition (retried; readiness needs schema ready): indexes via createIndexes only (scans.request_id unique partial; image.digest+state+finished_at; customer_ids+finished_at; state+queued_at; TTL on `db_checks.at` from `SCANNER_DB_CHECKS_RETENTION` 30d, collMod on change); conflicting index = ERROR + not ready, never dropped; `schema_version` via upsert + $setOnInsert, newer stored = not ready, older = migrate then set
- [x] P5-4 Repositories behind interfaces, with fakes for unit tests
- [x] P5-5 (follow-up: upload first, delete the file when the scan save fails, delete the previous file on retry, metadata `scan_id` and `uploaded_at`) GridFS for reports above the size threshold
- [x] P5-6 Persist DB state and checks in Mongo: `db_state` per instance and kind (`<instance_id>:<kind>`, `SCANNER_INSTANCE_ID` default hostname), `db_checks` with `instance_id`; memory first, updater keeps running while Mongo is down; flush on every Mongo up transition; load at startup but ignore stored confirmation when the stored digest differs from disk; bounded `db_checks` buffer drops oldest and logs the count
- [x] P5-7 Integration tests against real Mongo

## Phase 6: Registry client
- [x] P6-1 Registry client using the robot account from config, reusing the Phase 3 OCI client and token flow (basic credentials to the token endpoint, cached tokens with expiry, single-flight per scope, bounded challenges); validate names (OCI rules); resolve `repository/name:tag` to a digest with HEAD and the four manifest media types, GET + sha256 fallback; store `media_type`
- [x] P6-2 Error mapping: 404 `image_not_found`, 401/403 `registry_auth_failed`, timeout/5xx `registry_unavailable`; `SCANNER_REGISTRY_TIMEOUT` 15s; one retry on network errors and 5xx only; WARN for `http://` registries
- [x] P6-3 Tests with a fake registry: token flow and expiry refresh, index vs plain manifest, missing digest header, 404, 401/403, endless challenge, redirect, timeouts, invalid names, redaction

## Phase 7: Scan runner
- [x] P7-1 Run Trivy (flags of DEMAND 6.2) on `registry/repository/name@digest`: env allowlist, credentials via `TRIVY_USERNAME`/`TRIVY_PASSWORD`; private 0600 output file; Trivy `--timeout` below `SCANNER_SCAN_TIMEOUT` plus a process-group kill; `SCANNER_SCAN_MAX_OUTPUT`; last 8 KiB of stderr, redacted; failure classes; per-worker cache dir with DB symlinks to the version directory, pinned while scanning
- [x] P7-2 Stream-parse the output; validate platform and severity strings; keep the requested result types (case-insensitive) and severities
- [x] P7-3 Summary counts for all severities of the requested result types
- [~] P7-4 (discovery done; upsert into `platforms` comes with the scan orchestration in P7-5) Platform discovery from all result types; `platforms_requested`/`found`/`not_found`; upsert `platforms`; set `has_more_platforms`
- [ ] P7-5 Stored finding shape (DEMAND 6.2), `SCANNER_SCAN_MAX_FINDINGS` with `truncated`; store inline or in GridFS
- [ ] P7-6 Log "triggering scan" and "scan done" (no findings); store timings, Trivy version, DB version; `trivy --version` at startup, readiness false without the binary
- [ ] P7-7 Tests: canned Trivy JSON fixtures; fake trivy executable (env allowlist without SCANNER_* secrets, timeout kill including children, huge output, exit codes, stderr redaction); DB swap during a scan; two concurrent Trivy processes; one manual real-image run (`manual` tag)

## Phase 8: Queue
- [ ] P8-1 Enqueue into `scans` (state queued); dedupe on digest plus options
- [ ] P8-2 Worker pool with atomic claim, lease and heartbeat (add the queue-claim index); call the on-demand refresh (P4-4) before each scan
- [ ] P8-3 Recovery of expired leases
- [ ] P8-4 Max queue length (429), per-scan timeout, graceful shutdown
- [ ] P8-5 Reserve the optional `priority` field (unused)
- [ ] P8-6 Tests: concurrency, crash recovery, dedupe

## Phase 9: REST API v2
- [ ] P9-1 Router and service-token auth middleware; wire `main.go`; log the fallback-interval WARN only when v2 is enabled; run the component tests (first `main.go` touch)
- [ ] P9-2 `POST /api/v2/scans`: validation (400 for `customer_data` > 64 KiB or > 100 `customer_ids`) and `request_id` idempotency
- [ ] P9-3 Cache decision (all conditions in DEMAND section 6) and cached response with `cached` and `db_unchanged`
- [ ] P9-4 `GET /api/v2/scans/{id}` with `not_found` (404), `queued`, `scanning`, `done`, `failed`
- [ ] P9-5 `GET /api/v2/scans` filters and paging (project out the report)
- [ ] P9-6 `GET /api/v2/db` (includes `db_age`)
- [ ] P9-7 `db` block in responses (updated_at, last_upstream_check_at, freshness)
- [ ] P9-8 API tests covering every row of the DEMAND response tables

## Phase 10: Health, logging, metrics
- [ ] P10-1 `GET /api/v2/health` computed from stored data (includes `db_age`; DB information for every instance)
- [ ] P10-2 Readiness and liveness: Mongo reachable (from the background ping flag, never a direct Mongo call), DB present
- [ ] P10-3 Verify all required log lines from DEMAND section 12
- [ ] P10-4 Prometheus metrics (including a `mongo_up` gauge from the ping flag)
- [ ] P10-5 Remove the FULL TRIVY REPORT debug log (`pkg/trivy/wrapper.go`) once v2 logging exists

## Phase 11: Hardening and acceptance
- [ ] P11-1 End-to-end run in docker compose (scanner, Mongo, mirror or fake mirror)
- [ ] P11-2 Walk the acceptance criteria below and record evidence in PROGRESS.md
- [ ] P11-3 Harbor adapter regression: existing tests pass and one manual Harbor scan works
- [ ] P11-4 Dockerfile (seed DB, volume) and config README for v2. The README must say: DNS servers are set with Docker's `dns:` setting (or `/etc/resolv.conf`); Go's resolver tries them in order. No DNS pool in our code. It must also say: Harbor robot usernames contain `$`, which needs escaping in compose files and shells. And: MongoDB write and read concern are set in `SCANNER_MONGO_URI` (for example `w=majority&readConcernLevel=majority`); the service uses no multi-document transactions
- [ ] P11-5 Secrets review: no tokens or passwords in logs, argv or MongoDB
- [ ] P11-6 List the upstream files touched, for future merges; run the component tests again
- [ ] P11-7 (low priority) Get a working golangci-lint for Go 1.26 and run `make lint`

## Acceptance criteria (from DEMAND section 13)
- [ ] AC1 New image: 202, then `queued`, `scanning`, `done`, with stored result and timings
- [ ] AC2 Same digest and unchanged DB: 200 `cached: true`, no Trivy process started
- [ ] AC3 After a DB update, the same digest is scanned again
- [ ] AC4 `force: true` always scans
- [ ] AC5 A new tag pointing to an already-scanned digest is a cache hit
- [ ] AC6 Unknown `scan_id` returns `not_found` (404)
- [ ] AC7 Blackholed mirror: pre-check fails within its timeout, fallback source tried, if all fail scan uses the old DB and responses say `stale`
- [ ] AC8 Pre-check logs show source, route, TLS and HTTP/2 results, no secrets
- [ ] AC9 `/api/v2/health` reflects Mongo, DB age, queue and scan stats; readiness false when Mongo is down
- [ ] AC10 New platforms appear in the `platforms` collection on first discovery
- [ ] AC11 Harbor adapter endpoints still pass their existing tests; output matches upstream except the documented `vendor_attributes.Trivy`
- [ ] AC12 `platforms: ["npm"]` returns only npm findings, sets `has_more_platforms`, still records other types
- [ ] AC13 A broader request than the cached scan triggers a new scan
- [ ] AC14 Trivy never downloads a DB during a scan
