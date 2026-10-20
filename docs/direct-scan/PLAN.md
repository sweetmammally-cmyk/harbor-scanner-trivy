# Implementation Plan: direct scan API for harbor-scanner-trivy

Spec: `DEMAND.md` (source of truth). Task list and state: `CHECKLIST.md`, `PROGRESS.md`.

## Principles

- **Bottom-up, each phase testable alone.** The DB pre-check and download module comes first: it needs no MongoDB or queue, and it fixes the hang problem.
- **Isolation from upstream.** New code lives in its own packages (proposed `pkg/v2/...`, confirmed in P0-3). Harbor adapter behaviour does not change. The v2 service is behind `SCANNER_V2_API_ENABLED`.
- **Interfaces at the seams** (state store, registry client, Trivy runner, clock) so unit tests use fakes and Mongo is only needed for integration tests.
- **Every phase ends green:** build, tests, checklist ticked, PROGRESS entry written.

## Proposed package layout (verify in Phase 0)

| Package | Responsibility |
|---|---|
| `pkg/v2/config` | env parsing, duration parser, DB sources |
| `pkg/v2/dbmgr` | pre-checks, route-aware transport, OCI DB download, atomic swap, updater loop, freshness |
| `pkg/v2/registry` | robot-account client, tag to digest resolution |
| `pkg/v2/store` | MongoDB client, repositories, indexes, GridFS |
| `pkg/v2/runner` | Trivy invocation, output parsing and filtering, platform discovery |
| `pkg/v2/queue` | Mongo-backed queue, workers, leases |
| `pkg/v2/api` | HTTP handlers, auth, cache decision |
| `pkg/v2/health` | health and metrics |

## Phases

### Phase 0: Orientation and baseline
Read the repo, record the real package map, Go version, logger, config pattern, how Trivy is invoked today, and CI. Run the existing build and tests for a baseline. Confirm the package layout, the Mongo test strategy (local Mongo via env var or testcontainers) and the libraries (Mongo driver, SOCKS5 support). Fill the Commands section in `CLAUDE.md`.
Exit: PROGRESS "Repo facts" filled, baseline recorded.

### Phase 1: Config and skeleton
Feature flag, config struct for all variables in DEMAND section 11, duration parser with the `d` suffix and the 3h fallback, DB sources parser (ordered, each with route: direct, HTTP proxy or SOCKS5).
Exit: config unit tests pass; v2 disabled by default changes nothing.

### Phase 2: DB pre-check module
Route-aware dialer (direct, HTTP proxy, SOCKS5). Stage runner with per-stage and overall timeouts. Stages in order: DNS, connect, TLS handshake (version, cipher, ALPN), HTTP/2 request to `/v2/`, then the DB manifest. `httptrace` timings. Log the effective source and route and every stage result, with secrets redacted.
Exit: tests with local servers (ok, blackhole, bad TLS, no HTTP/2, HTTP proxy, SOCKS5) pass; a blackholed source fails within its timeout.

### Phase 3: DB download module
Decision to record in P3-1: raw `net/http` against the OCI distribution API using our transport (recommended, so pre-checks and downloads share one route implementation) versus a registry library. Upstream check by comparing the remote manifest digest with the stored one. Download with timeout, verify digest, extract `trivy.db` and `metadata.json` to a temp dir, swap atomically. Seed DB support. Fallback across sources; all failed means degraded mode, ERROR log, keep the old DB. Java DB follows the same flow.
Exit: tests with a fake registry (success, wrong digest, truncated, hang mid-download, fallback to second source, all sources fail).

### Phase 4: Updater and freshness
Interval loop (first run at startup, single-flight), state (`last_upstream_check_at`, mode, active source) behind an interface, freshness `ok|stale` from `last_upstream_check_at` versus `max_db_age`, on-demand bounded refresh. Fake clock tests.
Exit: freshness and interval behaviour verified, including the 3h fallback.

### Phase 5: MongoDB data plane
Client, hard-dependency behaviour, collections `scans`, `platforms`, `db_state`, `db_checks`, indexes and the TTL index, repositories behind interfaces, GridFS for large reports, persist DB state and checks in Mongo (replace the in-memory implementation from Phase 4).
Exit: integration tests against a real Mongo pass.

### Phase 6: Registry client
Robot account from config, resolve `repository/name:tag` to a digest with a manifest HEAD, map errors (not found, unauthorized, timeout).
Exit: tests with a fake registry.

### Phase 7: Scan runner
Run Trivy with its DB updates disabled, JSON output, credentials via environment, timeout and kill. Parse output, keep only the requested result types and severities, compute summary counts for all severities of the requested types, discover platforms from all result types and upsert them, set `has_more_platforms`, store inline or GridFS, log "triggering scan" and "scan done" with duration and store timings.
Exit: tests with canned Trivy JSON fixtures; one manual run against a real image.

### Phase 8: Queue
Enqueue into `scans`, dedupe on digest plus options, worker pool with atomic claim, lease and heartbeat, recovery of expired leases, max queue length (429), per-scan timeout, graceful shutdown, reserved but unused `priority` field.
Exit: concurrency, crash-recovery and dedupe tests pass.

### Phase 9: REST API v2
Router and service-token auth, `POST /api/v2/scans` on the tag's document (idempotency from the document identity; `request_id` is a correlation id), cache decision with renewal and copy hits (all conditions in DEMAND section 6), `GET /api/v2/scans/{id}` with the five states, `GET /api/v2/scans` filters and paging, `GET /api/v2/db`, the `db` block in responses.
Exit: API tests cover every row of the DEMAND response tables.

### Phase 10: Health, logging, metrics
`/api/v2/health` from stored data, readiness and liveness, verify the required log lines (DEMAND section 12), Prometheus metrics.
Exit: health reflects Mongo down, DB missing and degraded mode.

### Phase 11: Hardening and acceptance
End-to-end in docker compose (scanner, Mongo, a mirror or fake mirror), walk acceptance criteria AC1 to AC14 with evidence, Harbor adapter regression, Dockerfile with seed DB and volume, config README, secrets review, list of upstream files touched.
Exit: all checklist items and acceptance criteria ticked.

### Phase 12: Staging and integration (owner's changes of 2026-10-20)
CI for the fork on every push, an integration guide for the backend's Temporal activity (Go), Prometheus alert rules with promtool tests, a startup log of every setting (secrets hidden, unknown `SCANNER_*` variables warned), one self-contained compose stack that works from `cp .env.example .env` (no staging host), and a real Harbor regression on a throwaway local Harbor that is removed afterwards.
Exit: CI green on every push; the guide and the alert rules are in `docs/direct-scan/`; the compose stack comes up from the example with both replicas ready, a scan and a hit; a scan from the local Harbor UI used this scanner and the local Harbor is gone again.

## Risks to watch

- Trivy CLI flags and output format differ by version: pin the version and record it in PROGRESS.
- Atomic DB swap while scans are running: decide the mechanism (versioned directory plus a pointer) in P3-4.
- Registry token auth differences across mirrors (anonymous bearer versus none): handle in the OCI client and cover with tests.
- Report size: test a very large fixture to prove the GridFS path.
