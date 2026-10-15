# CHECKLIST

Legend: `[ ]` todo, `[~]` in progress (note where you stopped in PROGRESS.md), `[x]` done (tests passed).
Update this file after every task. Details: `PLAN.md`. Spec: `DEMAND.md`.

## Phase 0: Orientation and baseline
- [x] P0-1 Read repo; record package map, Go version, logger, config pattern, how Trivy is invoked, CI in PROGRESS "Repo facts"
- [ ] P0-2 Run existing build and tests; record exact commands and baseline result
- [ ] P0-3 Confirm or adjust the package layout (`pkg/v2/...`); record decision
- [ ] P0-4 Decide Mongo test strategy and libraries (Mongo driver, SOCKS5); record decision
- [ ] P0-5 Fill the Commands section of `CLAUDE.md`

## Phase 1: Config and skeleton
- [ ] P1-1 Feature flag `SCANNER_V2_API_ENABLED`; v2 wiring off by default
- [ ] P1-2 Config struct and env parsing for all variables in DEMAND section 11
- [ ] P1-3 Duration parser with `d` support; unset or invalid check interval falls back to 3h with a WARN log
- [ ] P1-4 `SCANNER_DB_SOURCES` parser (ordered; route direct, HTTP proxy or SOCKS5), validation, redacted printing
- [ ] P1-5 Unit tests for config

## Phase 2: DB pre-check module
- [ ] P2-1 Route-aware dialer: direct, HTTP proxy (CONNECT), SOCKS5
- [ ] P2-2 Stage runner with per-stage timeouts and an overall deadline; result struct (stage, ok, timing, detail)
- [ ] P2-3 Stages in order: DNS, connect, TLS handshake (version, cipher, ALPN), HTTP/2 GET `/v2/`, DB manifest request
- [ ] P2-4 `httptrace` timings: DNS, connect, TLS, first byte, total
- [ ] P2-5 Log effective source, route and each stage result; redact credentials and Authorization
- [ ] P2-6 Tests: ok server, blackhole (timeout), TLS failure, no HTTP/2, HTTP proxy, SOCKS5, redaction
- [ ] P2-7 Manual debug entrypoint or test helper to run a pre-check against one source

## Phase 3: DB download module
- [ ] P3-1 OCI client over our transport (token auth if needed, manifest, blob); record raw-HTTP vs library decision
- [ ] P3-2 Upstream check: compare remote manifest digest with the stored one
- [ ] P3-3 Download DB layer with timeout, verify digest, extract `trivy.db` and `metadata.json` to a temp dir
- [ ] P3-4 Atomic swap; in-flight scans keep the old copy (record mechanism)
- [ ] P3-5 Seed DB support; service not ready until a DB exists
- [ ] P3-6 Source fallback loop; all failed means degraded mode, ERROR log, old DB kept
- [ ] P3-7 Java DB through the same flow
- [ ] P3-8 Parse `metadata.json` (UpdatedAt, NextUpdate, Version, DownloadedAt)
- [ ] P3-9 Tests with a fake registry: success, wrong digest, truncated, hang mid-download, fallback to second source, all sources fail

## Phase 4: Updater and freshness
- [ ] P4-1 Interval loop, first run at startup, single-flight
- [ ] P4-2 State behind an interface: last_upstream_check_at, mode, active source (in-memory first)
- [ ] P4-3 Freshness `ok|stale` from last_upstream_check_at versus `max_db_age`
- [ ] P4-4 On-demand bounded refresh when a request's `max_db_age` is exceeded
- [ ] P4-5 Fake-clock tests (including the 3h fallback)

## Phase 5: MongoDB data plane
- [ ] P5-1 Mongo client, connect, ping; hard-dependency behaviour (not ready, 503)
- [ ] P5-2 Models and collections: `scans`, `platforms`, `db_state`, `db_checks`
- [ ] P5-3 Indexes (scans.request_id unique; image.digest+state+finished_at; customer_ids+finished_at; state+queued_at) and TTL on `db_checks`
- [ ] P5-4 Repositories behind interfaces, with fakes for unit tests
- [ ] P5-5 GridFS for reports above the size threshold
- [ ] P5-6 Persist DB state and checks in Mongo (replace the in-memory implementation)
- [ ] P5-7 Integration tests against real Mongo

## Phase 6: Registry client
- [ ] P6-1 Registry client using the robot account from config; resolve `repository/name:tag` to a digest (manifest HEAD)
- [ ] P6-2 Error mapping: not found, unauthorized, timeout
- [ ] P6-3 Tests with a fake registry

## Phase 7: Scan runner
- [ ] P7-1 Run Trivy with DB updates disabled and JSON output; credentials via env, never argv; timeout and kill
- [ ] P7-2 Parse output; keep only requested result types and severities
- [ ] P7-3 Summary counts for all severities of the requested result types
- [ ] P7-4 Platform discovery from all result types; upsert `platforms`; set `has_more_platforms`
- [ ] P7-5 Store the result inline or in GridFS
- [ ] P7-6 Log "triggering scan" and "scan done" with duration; store timings
- [ ] P7-7 Tests with canned Trivy JSON fixtures; one manual run on a real image

## Phase 8: Queue
- [ ] P8-1 Enqueue into `scans` (state queued); dedupe on digest plus options
- [ ] P8-2 Worker pool with atomic claim, lease and heartbeat
- [ ] P8-3 Recovery of expired leases
- [ ] P8-4 Max queue length (429), per-scan timeout, graceful shutdown
- [ ] P8-5 Reserve the optional `priority` field (unused)
- [ ] P8-6 Tests: concurrency, crash recovery, dedupe

## Phase 9: REST API v2
- [ ] P9-1 Router and service-token auth middleware
- [ ] P9-2 `POST /api/v2/scans`: validation and `request_id` idempotency
- [ ] P9-3 Cache decision (all conditions in DEMAND section 6) and cached response with `cached` and `db_unchanged`
- [ ] P9-4 `GET /api/v2/scans/{id}` with `not_found` (404), `queued`, `scanning`, `done`, `failed`
- [ ] P9-5 `GET /api/v2/scans` filters and paging
- [ ] P9-6 `GET /api/v2/db`
- [ ] P9-7 `db` block in responses (updated_at, last_upstream_check_at, freshness)
- [ ] P9-8 API tests covering every row of the DEMAND response tables

## Phase 10: Health, logging, metrics
- [ ] P10-1 `GET /api/v2/health` computed from stored data
- [ ] P10-2 Readiness and liveness: Mongo reachable, DB present
- [ ] P10-3 Verify all required log lines from DEMAND section 12
- [ ] P10-4 Prometheus metrics

## Phase 11: Hardening and acceptance
- [ ] P11-1 End-to-end run in docker compose (scanner, Mongo, mirror or fake mirror)
- [ ] P11-2 Walk the acceptance criteria below and record evidence in PROGRESS.md
- [ ] P11-3 Harbor adapter regression: existing tests pass and one manual Harbor scan works
- [ ] P11-4 Dockerfile (seed DB, volume) and config README for v2
- [ ] P11-5 Secrets review: no tokens or passwords in logs, argv or MongoDB
- [ ] P11-6 List the upstream files touched, for future merges

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
- [ ] AC11 Harbor adapter endpoints still pass their existing tests
- [ ] AC12 `platforms: ["npm"]` returns only npm findings, sets `has_more_platforms`, still records other types
- [ ] AC13 A broader request than the cached scan triggers a new scan
- [ ] AC14 Trivy never downloads a DB during a scan
