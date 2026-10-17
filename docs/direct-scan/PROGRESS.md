# PROGRESS: state and changelog

Claude Code: read this file FIRST in every session, and update it after every task (see `CLAUDE.md` section 3).
Newest changelog entries go at the top of the Changelog.

## Current state

- Phase: 10 (health, logging, metrics); Phase 9 complete except the v1 component test run
- Last completed task: P10-1
- In progress: none
- Next task: P10-4
- Blockers / questions for the user: the v1 component tests wait for the owner to rename the local Harbor container `redis` to `redis-harbor-local` (still named `redis` at the last check); P9-1 and P9-8 stay `[~]` until then.
- Last updated: 2026-10-17

## Repo facts (filled in by Phase 0)

- Go version: `go 1.26.4` (go.mod). Module path: `github.com/aquasecurity/harbor-scanner-trivy`.
- Package map:
  - `cmd/scanner-trivy/main.go`: builds slog logger, reads config, wires Redis, Trivy wrapper, controller, queue worker and API server, handles SIGINT/SIGTERM.
  - `pkg/etc`: config (`Config` struct, `GetConfig`, `Check`, `LogLevel`).
  - `pkg/http/api`: `server.go` (HTTP server, TLS) and `base_handler.go` (JSON error helpers).
  - `pkg/http/api/v1`: Harbor adapter handler; gorilla/mux router with `/api/v1/scan`, `/api/v1/scan/{id}/report`, `/api/v1/metadata`, `/probe/healthy`, `/probe/ready`, plus `/metrics`.
  - `pkg/harbor`: Harbor API models. `pkg/job`: scan job model.
  - `pkg/queue`: Redis job queue (enqueuer, worker). `pkg/persistence` + `pkg/persistence/redis`: job store. `pkg/redisx`: Redis client.
  - `pkg/scan`: controller (runs a job) and transformer (Trivy report to Harbor report).
  - `pkg/trivy`: `Wrapper` that builds and runs the `trivy` command and parses its output; `target.go` (image or SBOM target).
  - `pkg/ext`: `Ambassador` (wraps exec, env, temp files, LookPath) so tests can mock the OS.
  - `pkg/mock`: testify mocks.
  - `test/integration` (build tag `integration`, testcontainers: Redis, registry), `test/component` (build tag `component`, docker-compose).
- Logger and config pattern: standard library `log/slog` with a JSON handler on stdout, set as default in `main.go`; level from `SCANNER_LOG_LEVEL` (`etc.LogLevel`). Code calls `slog.Info/Debug/...` with `slog.String(...)` attrs. Config is one struct per area with `env:"..." envDefault:"..."` tags parsed by `github.com/caarlos0/env/v6` (`etc.GetConfig`), then validated by `etc.Check`. Errors are wrapped with `fmt.Errorf("...: %w", err)` or `xerrors.Errorf`.
- How Trivy is invoked today: `pkg/trivy/wrapper.go` `prepareScanCmd` builds `exec.Command("trivy", "image"|"sbom", ...)` with `--no-progress --severity --vuln-type --format --output <tmp file> --cache-dir --timeout` and optional flags (`--skip-db-update`, `--skip-java-db-update`, `--offline-scan`, `--db-repository`, ...). The env comes from `ambassador.Environ()`; registry credentials go in as env vars `TRIVY_USERNAME`/`TRIVY_PASSWORD` or `TRIVY_REGISTRY_TOKEN`, never argv. It runs through `ambassador.RunCmd` (`cmd.CombinedOutput`), with no Go-side context or kill; only Trivy's own `--timeout` (`SCANNER_TRIVY_TIMEOUT`, default 5m) limits it. The JSON report is read from the temp file.
- Trivy version pinned: `TRIVY_VERSION=0.74.0` in `Dockerfile` and in `make setup`; this is the target (owner, fourteenth round). The local dev machine has trivy 0.71.2 on PATH; 0.74.0 checks used the binary copied from `aquasec/trivy:0.74.0`.
- Build / test / lint commands:
  - build: `go build ./...` (binary: `make build`)
  - unit tests: `make test` (= `go test -v -short -race -coverprofile=coverage.txt -covermode=atomic ./...`)
  - integration tests: `make test-integration` (= `go test -count=1 -v -tags=integration ./test/integration/...`, needs Docker)
  - component tests: `make test-component` (builds the Docker image first)
  - vet: `go vet ./...`
  - lint: `make lint` needs `./bin/golangci-lint` (not installed locally)
- CI: `.github/workflows/build.yml` on push to main and PRs: yamllint, `make setup`, `make lint`, `make test`, `make test-integration`, `make test-component`, goreleaser snapshot. Changes only under `docs/**` or `*.md` skip CI.
- Baseline after P0-6: `make test` and `make test-integration` pass (component tests and lint still not run). Files that `gofmt -l` already flagged before our work (`pkg/etc/config.go`, `pkg/etc/config_test.go`, `pkg/http/api/v1/handler.go`, `pkg/trivy/model.go`) are left alone.
- Baseline test result before our changes (2026-10-15, HEAD `3d447af`, code same as `f917cc0`):
  - `go build ./...`: OK. `go vet ./...`: OK.
  - `make test`: **FAIL**. `TestWrapper_Scan` (pkg/trivy) and `TestTransformer_Transform` (pkg/scan) fail; everything else passes. Cause: commit `0c87038` added `Vulnerability.Target/Type` and the `Trivy` vendor attribute without updating tests. On upstream `2691434` all `./pkg/...` tests pass (checked in a temporary worktree).
  - `make test-integration`: **FAIL** in `test/integration/api` (`TestRestAPI`: Harbor report now has `vendor_attributes.Trivy`, same cause). `test/integration/persistence/redis`: OK.
  - `make test-component`: not run (needs a full image build; slow).
  - `make lint`: not run (golangci-lint not installed; pinned v1.21.0 is too old for Go 1.26).

## Decisions

Record decisions here with date and reason (package layout, Mongo test strategy, OCI client approach, DB swap mechanism, anything the user answered). If a decision changes the spec, also propose the edit to `DEMAND.md`.

- 2026-10-17 (owner, Phase 10 and follow-ups; DEMAND v0.19 sections 5.0, 5.5, 11, 12):
  - Component tests: the owner renames the local Harbor container `redis` to `redis-harbor-local` for the run and back afterwards; we never remove or modify it. On a failure, run the same tests in a separate worktree at the P0-6 commit to see whether it predates v2; `vendor_attributes.Trivy` (KEEP) failures are fixed in test expectations only. Tick P9-1/P9-8 when green or when a failure is proven older and documented.
  - New error code `too_many_requests` (429, `Retry-After: 1`) for the in-flight cap; `queue_full` only for a full queue.
  - P11-4 sizing: two DB copies on disk (v1's Trivy cache and `SCANNER_V2_CACHE_DIR`).
  - Liveness trivial; readiness conditions (Mongo, schema, Trivy DB, trivy binary, shutting down, required Java DB; degraded mode stays ready); v1 probes unchanged with v2 disabled.
  - `GET /api/v2/health` ok/degraded/unhealthy with the rules of DEMAND 5.5; `SCANNER_HEALTH_QUEUE_STUCK_AFTER` (10m); failure-rate window of the last 20 scans on this replica, at least 10 samples, over 50%.
  - Metrics on the adapter's `/metrics` with the list and label rules of DEMAND 12; `Queue.Stats` cached 10s.
  - P10-5 removes only the FULL TRIVY REPORT log. P10-3 adds log-capture tests and a no-secret test over logs, metrics and the health body.
- 2026-10-17 (owner, complete Phase 9 decisions; supersede earlier Phase 9 messages; DEMAND v0.18 sections 5, 6, 10, 11, 13 and 14):
  - Corrections to P8-7: the copy-hit lookup matches `result.digest` only (own index); `image.digest` is the latest request's digest. A copy source may be queued/scanning; its GridFS content is copied to a new file; a vanished source file -> lookup once more, then a miss.
  - P9-1: bearer auth, constant-time compare of hashes, one token of at least 32 characters (startup fails otherwise when enabled), 401 with `WWW-Authenticate`, `/probe/*` open, `/api/v2/health` and `/api/v2/db` need the token. `/api/v2/` routed only when enabled. Both startup WARNs only when v2 is enabled. Startup order store -> schema -> updater -> workers -> HTTP; shutdown readiness false -> HTTP drain -> workers (grace, release) -> updater -> Mongo close. Hygiene: 1 MiB body, JSON content type, strict decoding, server timeouts, `SCANNER_V2_MAX_INFLIGHT` (32) -> 429 + `Retry-After`, one log line per request, `X-Request-ID`. Error shape `{"error": {"code", "message"}}` with the ten codes of DEMAND 5.0.
  - P9-2: validation rules of DEMAND 5.1; order auth -> validate -> not ready -> resolve -> active-scan check -> cache -> enqueue; covered active scan -> 200 even with `force` (document unchanged), otherwise 409 `Retry-After: 5`.
  - P9-3: hit conditions and renewal; copy hit; views filtered to the request (findings, summary from `summary_by_platform`, found/not found/has more from `image_platform_types`); a broader severity is a miss.
  - P9-4: id format, 404 `{"state": "not_found"}`, `Retry-After: 2` while queued/scanning, findings only when done, `previous {confirmed_at, digest, summary}`, failed shows class and a short sanitized message, optional `platforms`/`severity` view filters.
  - P9-5: filters, immutable `created_at`, order `created_at` desc then `_id` desc, keyset pagination (limit 50, max 200, opaque cursor), no findings/report; indexes (customer_ids, created_at), result.digest, image.digest, created_at, state; explain test; stable pagination.
  - P9-6/P9-7: `GET /api/v2/db` from this instance's memory plus other instances best effort; `db` block from stored values, local state while no result.
  - Our choices within these rules (to confirm): error statuses 413 (body too large) and 415 (content type) carry `invalid_request`; the in-flight cap answers `queue_full` with `Retry-After: 1`; `queue_full` and `registry_unavailable` use `Retry-After: 10`; MongoDB down or a failed MongoDB call is `store_unavailable`, schema not ready or no DB installed is `not_ready`; a GET view filter outside the stored scope is 400; the `failed` message is a fixed text per failure class (the stored detail may hold redacted stderr); `platform` list filter matches `result.image_platform_types`; the `state` index is the existing `(state, queued_at)`; the v2 DBs and worker caches live in a new `SCANNER_V2_CACHE_DIR` (default `/home/scanner/.cache/scanner-v2`), apart from the adapter's Trivy cache, because the adapter's Trivy may update its own DB there; a POST extends its own write deadline (the default `SCANNER_API_SERVER_WRITE_TIMEOUT` of 15s is shorter than a registry resolve with its retry); `runner.MaxPlatforms` drops from 50 to 20.
- 2026-10-17 (owner): data model "current state only, one record per image tag" (replaces Phase 9 items 1, 7, 8, 10, 12 and 16 of a message this session never received; recorded in DEMAND v0.17 sections 4, 5, 6, 9, 10, 11, 13 and 14).
  - `scans` holds one document per tag, `_id` = scan_id = lowercase hex sha256 of `"<repository>/<name>:<tag>"`; no history; nothing deployed, so no migration (schema version 3, dev databases recreated).
  - Removed: `active_key` and its unique index, the `request_id` unique index, `prior_request_id`, the fingerprint/409 idea. `request_id` is an optional correlation id (1-128 chars) stored as `last_request_id`.
  - Enqueue = insert the first time, then a conditional update only when the state is not queued/scanning; the last result stays until a new scan succeeds. While queued/scanning: same digest and covered -> 200 with that state, otherwise 409 `scan_in_progress` with `Retry-After`. Same digest: scope = union of stored and requested platforms/severities; moved tag: the request's scope.
  - Success replaces the result and deletes the previous GridFS file (best effort, after the save); failure sets failed with class and sanitized message and keeps the last good result.
  - Cache (P9-3): POST order auth -> validate -> not ready -> resolve -> cache -> enqueue; hit conditions on the tag's document; a hit renews `confirmed_at`, `db.freshness` and the request fields (no new document); else copy hit from another document with the same digest (copies independent). `cached`/`db_unchanged` only in POST responses. Validity by the DB version rule, never by time.
  - `db` block: `updated_at`, `last_upstream_check_at`, `confirmed_at`, `freshness`; stored values, not recomputed on read; the local DB state while a tag has no result.
  - Auth: one `SCANNER_V2_AUTH_TOKEN`, constant-time compare, at least 32 characters; no `_PREVIOUS` token.
  - Implementation choices (ours, to confirm): the last successful scan is a `result` sub-document (`digest`, `platforms`, `severity`, `scanned_platform`, `trivy_version`, `image_platform_types`, `summary`, `summary_by_platform`, `truncated`, `report`/`report_gridfs_id`) next to top-level `db` and `confirmed_at`, so a failed attempt cannot touch it; `image.digest` is the digest of the last enqueue and `result.digest` the scanned one (the copy-hit lookup matches both); the existing `image_digest_state_finished_at` index serves the digest lookup; `platforms_found`/`platforms_not_found`/`has_more_platforms` are no longer stored but derived per request from `image_platform_types` (the stored scope can be wider than a request).
- 2026-10-15 (owner): settings and DB download, now in DEMAND v0.5 sections 7.3, 7.4 and 11.
  - `SCANNER_MONGO_URI` and `SCANNER_MONGO_DB` are required, with no defaults; when v2 is enabled and either is missing, startup fails with a clear error.
  - Defaults: workers 1, max queue length 100, `SCANNER_SCAN_TIMEOUT` 10m, `max_db_age` 6h, pre-check timeouts DNS 5s, CONNECT 5s, TLS 5s, HTTP 10s, MANIFEST 10s, TOTAL 30s. All overridable by env.
  - `SCANNER_DB_SOURCES=repo|route,repo|route`, route = `direct`, `http://host:port` or `socks5://host:port`. Sources form an ordered pool mixing public registries and our mirrors. `SCANNER_JAVA_DB_SOURCES` is optional, same format and flow.
  - Every download is gated by the pre-check; a failed source is never downloaded from. After a passed pre-check: stall timeout `SCANNER_DB_DOWNLOAD_STALL_TIMEOUT` (30s) and overall cap `SCANNER_DB_DOWNLOAD_TIMEOUT` (15m, safety net only).
  - The FULL TRIVY REPORT debug log stays until v2 logging exists (task P10-5).
  - Baseline must be green before P1-2 (task P0-6).
  - `vendor_attributes.Trivy`: KEEP. Tests updated; AC11 reworded to "adapter output matches upstream except the documented vendor attribute" (DEMAND section 13).
- 2026-10-15 (owner, second round):
  - P3-6: when v2 is enabled and `SCANNER_DB_SOURCES` is empty, refuse to start with a clear error. A fixed-DB mode, if ever needed, will be a separate explicit flag later. Implemented as a config check next to the Mongo checks.
  - History: the CHECKLIST.md restore was folded into the P0-3 commit (no push had happened). New CLAUDE.md rule: run `git diff --stat` before every commit and check that no doc file was emptied or deleted.
  - The fallback-interval WARN is logged only when v2 is enabled; fixed in P9-1.
  - P11-7 (low priority): working golangci-lint for Go 1.26. Run the component tests in P9-1 (first `main.go` touch) and again in Phase 11.
  - Pre-check HTTP/2 policy: HTTP/2 is required by default for a source to pass. Per-source opt-out, chosen by the owner from three proposals: optional third field `repo|route|options`, where options is a `;`-separated list. Only option today: `allow-http1`. Two-field entries keep working; unknown options are a startup error. The pre-check result always records the negotiated protocol. DEMAND sections 7.3 and 11 updated.
- 2026-10-15 (owner, fourteenth round): DEMAND v0.16 (6, 6.2, 9, 11).
  - Target Trivy is the Dockerfile pin, 0.74.0: regenerate the fixtures, diff against 0.71.2, re-run the real-image checks (task P7-8). A different Trivy version is a cache miss.
  - `SCANNER_SCAN_PLATFORM` (default `linux/amd64`) goes to Trivy (`--platform`), is stored as `scanned_platform` and is part of the cache and dedupe keys; no manifest for it = `platform_not_found`. Multi-arch handling stays deferred.
  - Phase 8: the scan document is the job; claim with `findOneAndUpdate`; leases on MongoDB's clock (`$$NOW`, MongoDB 4.2+); lease 60s, heartbeat 20s, writes fenced on `_id` + `worker` + `attempt`, a lost lease discards the result and kills Trivy; reaper every 30s, `SCANNER_QUEUE_MAX_ATTEMPTS` 3 then `worker_lost`; `active_key` with a unique partial index for dedupe (schema version bump); failed scans move `request_id` to `prior_request_id`; queue full 429 with `Retry-After`; poll 2s with jitter plus in-process wake-up, no change streams; no claim while not ready; on-demand refresh before each scan; SIGTERM grace `SCANNER_SHUTDOWN_GRACE` 30s then kill and release; completion retry up to 2 minutes; queue metrics; only the reserved `priority` field.
- 2026-10-15 (owner, thirteenth round): DEMAND v0.15 (6.2, 7.5, 11).
  - A duplicate source in `SCANNER_DB_SOURCES` / `SCANNER_JAVA_DB_SOURCES` is rejected at parse time. The extra 401 per request of the shared OCI client is a known, accepted cost.
  - Scan runner rules (DEMAND 6.2): env allowlist; credentials in `TRIVY_USERNAME`/`TRIVY_PASSWORD`; per-worker cache dir with symlinks to the pinned version directory; version UpdatedAt and digest stored with the scan; one Trivy run with `--scanners vuln`, no `--severity`, JSON to a private 0600 file, `--timeout` below `SCANNER_SCAN_TIMEOUT` plus a process-group kill; `SCANNER_SCAN_MAX_OUTPUT` 256 MiB; last 8 KiB of stderr, redacted; failure classes `trivy_timeout`, `trivy_exit_error`, `output_too_large`, `output_invalid`, `db_missing`, `java_db_missing`; platform and severity validation; `platforms_requested`/`found`/`not_found`; stored finding fields; `SCANNER_SCAN_MAX_FINDINGS` 10000 with `truncated`; logging without findings; `trivy --version` at startup and readiness.
  - Checked with the local Trivy 0.71.2 before coding (scratchpad experiments):
    - `--username`/`--password` bind to `TRIVY_USERNAME`/`TRIVY_PASSWORD` (the help says to use `TRIVY_PASSWORD` for security). For an `http://` registry, upstream passes `--insecure` (`pkg/trivy/wrapper.go`); the help shows `--insecure` ("allow insecure server connections"). Not run against a real plain-http registry here: go-containerregistry allows http to localhost anyway, so a local test proves nothing; to verify in the compose end-to-end (P11-1).
    - `--image-src` defaults to `docker,containerd,podman,remote`: the runner passes `--image-src remote`, so the scanned image is always the registry's digest. Trivy also makes a version-check call unless `--skip-version-check`.
    - Result types without findings still appear in the JSON with `--list-all-pkgs=false` (alpine:3.22 with 0 vulnerabilities; a `pip` result with 0 vulnerabilities), so the runner uses `--list-all-pkgs=false` (smaller output; the default is true).
    - A `.jar` (log4j-core 2.14.1 metadata) with no Java DB: `trivy rootfs`/`image` stops with exit 1, "The first run cannot skip downloading Java DB" / "Unable to initialize the Java DB". There is no clean skip (only `--skip-files "**/*.jar"`, which hides findings and is analyzer-level restriction, deferred), so it is classified `java_db_missing`. `trivy fs` does not analyse jars at all.
  - Version mismatch to raise with the owner: the Dockerfile pins Trivy 0.74.0, the owner's message says 0.71.2 (the local binary).
- 2026-10-15 (owner, twelfth round): DEMAND v0.14 (5.1, 6.1, 10, 11).
  - `db_checks` rows get a deterministic `_id` "<instance>:<kind>:<run_started_at>:<source>" and are upserted, so a repeated flush never duplicates them.
  - `SCANNER_INSTANCE_ID` falling back to the hostname logs a WARN. New `SCANNER_DB_STATE_RETENTION` (7d): TTL on `db_state.updated_at`, `collMod` on change; startup fails if it is shorter than twice `SCANNER_DB_CHECK_INTERVAL`.
  - First ready after boot: if no update run has completed yet, load the stored state (with the disk check) before writing; otherwise write memory.
  - Phase 6: reuse the Phase 3 OCI client and token flow (basic credentials to the token endpoint, scope `repository:<repo>:pull`, cached tokens, single-flight per scope, bounded challenges); HEAD with the four manifest media types, `Docker-Content-Digest` or GET + sha256 of the exact bytes; store `media_type`; P7 scans `registry/repo/name@digest`; names validated against the OCI rules (400), resolved synchronously in `POST /api/v2/scans`; `SCANNER_REGISTRY_TIMEOUT` 15s, one retry on network errors and 5xx, none on 401/403/404; errors `image_not_found` (404), `registry_auth_failed` (502), `registry_unavailable` (503 + retry hint); `http://` registries allowed with one WARN; credentials and tokens never logged; README notes the `$` in robot names.
- 2026-10-15 (owner, eleventh round): DEMAND v0.13 (5.1, 5.4, 5.5, 10, 11).
  - The inline report limit stays a code constant of 8 MiB, measured on the BSON-encoded report. P9-2 rejects (400) `customer_data` > 64 KiB and > 100 `customer_ids`; P9-5 list queries project out the report.
  - GridFS: upload first, then save the scan document; if the save fails, delete the file at once (best effort). File metadata `scan_id` and `uploaded_at`. A retry for the same `scan_id` deletes the previous file first. Retention stays deferred.
  - `db_state` is one document per instance and DB kind (`_id` "<instance_id>:<kind>"), `SCANNER_INSTANCE_ID` (default hostname); `db_checks` rows carry `instance_id`; health shows every instance.
  - P5-6 behaviour: the updater keeps running while Mongo is down with state in memory; on every Mongo up transition the latest state is flushed even without a new run; at startup the instance's stored state is loaded, but when its digest differs from the disk's, `last_confirmed_current_at` and `newer_available` are ignored (disk is the source of truth); `db_checks` are best effort with a bounded buffer that drops the oldest and logs how many.
- 2026-10-15 (owner, tenth round): DEMAND v0.12, sections 10 and 11.
  - Reconnection: rely on the driver's own reconnection, no custom backoff loop. DEMAND section 11 now says "the driver reconnects automatically".
  - Ensure schema (P5-3): run at startup if Mongo is up and on every up transition, retried until it succeeds; readiness needs "schema ready" too. `createIndexes` is the only index mechanism. `schema_version` uses an upsert with `$setOnInsert`; stored newer than code means not ready with an ERROR; stored older means migrations (none yet), then set the version. `request_id` unique index is partial (`{request_id: {$type: "string"}}`). TTL on `db_checks.at` from `SCANNER_DB_CHECKS_RETENTION` (30d), updated with `collMod`. An existing index with the same name but other options: ERROR naming it, not ready, never dropped. The queue-claim index belongs to P8.
  - Consequence found while planning P5-3: `Scan.RequestID` must be `omitempty`, otherwise scans without a request id store `""` (a string) and collide on the partial unique index.
- 2026-10-15 (owner, ninth round): MongoDB client (DEMAND v0.11, section 11).
  - Missing `SCANNER_MONGO_URI` / `SCANNER_MONGO_DB` stays a startup config error. Mongo only unreachable: no exit, readiness false, v2 API 503, DB updater keeps running, the client reconnects.
  - Timeouts: `SCANNER_MONGO_CONNECT_TIMEOUT` 5s, `SCANNER_MONGO_SERVER_SELECTION_TIMEOUT` 5s, `SCANNER_MONGO_OPERATION_TIMEOUT` 10s; every Mongo call takes a context with a deadline.
  - Readiness reads a flag set by a background ping every 5s; probes never call Mongo. A `mongo_up` gauge comes in P10-4.
  - No multi-document transactions. Write and read concern come from the connection string (README in P11-4).
  - The connection string is never logged or put in errors; redaction test includes driver errors that quote the URI.
  - P5-3: indexes are created idempotently at startup (safe with several replicas at once), plus a `schema_version` document.
  - Tests: unit tests with a fake; integration tests with `mongo:7`, including "unreachable at startup: readiness false, no exit" and "Mongo comes back: readiness true".
  - Implementation note on "reconnects with exponential backoff": the Go driver connects lazily and reconnects by itself (its server monitor keeps probing), so the client is created once and never recreated; the 5s ping only drives readiness. (Confirmed by the owner in the tenth round.)
- 2026-10-15 (owner, eighth round): DEMAND v0.10, 7.4 and 11.
  - Write-failure tests use an injected writer (they must work as root); same assertions.
  - The installed digest must be readable from disk; it already is (`manifest-digest` file per version directory, read by `installedDigest`); a test proves a new updater with empty state does not download when the digest is equal.
  - P4-3 connects freshness to the stored state.
  - On-demand refresh (P4-4): runs in the scan worker before the scan; waits at most `SCANNER_ONDEMAND_REFRESH_WAIT` (60s), then the scan proceeds with the old DB as `stale` while the refresh continues; reuses a run that finished within `SCANNER_ONDEMAND_REFRESH_MIN_GAP` (60s); no on-demand refresh while degraded (the retry interval governs, freshness stays `stale`).
  - Phase 5 (implement in P5-6): the DB updater keeps running while MongoDB is down; state stays in memory and is written to MongoDB when it is back; the service is still not ready while MongoDB is down.
- 2026-10-15 (owner, seventh round): the free disk space check (P3-10) is dropped. It was removed with a revert commit (`9f42746`) because P4-1 was already built on top; the Java DB download cap from the same commit was kept. DEMAND v0.9, 7.3, 7.4 and 11 updated.
  - A full disk during install fails as `install_error`, leaves no partial directory, keeps the old DB, and results in `degraded` + `newer_available`. Implementation: file errors (`*fs.PathError`) while extracting are marked `errLocalDisk` in `downloadDB`, and `update` reports them as `install_error`; network and layer read errors stay `download_error`.
  - No `SCANNER_JAVA_DB_SOURCES` means no Java DB at all, seed included (DEMAND section 11).
  - The disk sizing notes below stay, as sizing information for P11-4 only.
- 2026-10-15 (owner, sixth round): DEMAND v0.8, 7.2, 7.3 and 11.
  - `SCANNER_DB_RETRY_INTERVAL`, default 15m, used while degraded; back to `SCANNER_DB_CHECK_INTERVAL` after a success.
  - `SCANNER_JAVA_DB_DOWNLOAD_TIMEOUT`, default 45m, for the Java DB; the Trivy DB keeps `SCANNER_DB_DOWNLOAD_TIMEOUT` (15m); the 30s stall timeout applies to both. Empty `SCANNER_JAVA_DB_SOURCES` means no Java DB is downloaded.
  - (Superseded by the seventh round: the free disk space check was dropped and reverted.)
- Disk sizing notes for P11-4 (Dockerfile, volume, README): the Trivy DB needs about 5 GB in the cache volume (current 1.62 GB, previous 1.62 GB, one download in progress 1.62 GB, plus headroom); the Java DB about 3x 1.55 GB more when enabled; the seed DB adds 1.6 GB to the image (plus 1.55 GB if a Java seed is baked in).
- 2026-10-15 (owner, fifth round): a source offered a different digest but nothing could be installed (DEMAND v0.7, 5.4, 7.2, 7.4).
  - Mode `degraded` (so the retry interval applies) and ONE ERROR "newer DB available but could not be installed" with each source's failure class. Replaces the WARN from P3-6.
  - Two timestamps: `last_upstream_check_at` (any source answered, diagnostic only) and `last_confirmed_current_at` (installed digest equals upstream, or just installed). Freshness (P4-3) uses `last_confirmed_current_at`.
  - `newer_available`: set when a different digest was offered and the install failed; cleared by the next install or confirmed-current check. While set, freshness is `stale` regardless of `max_db_age`. Scans keep running with the old DB and say `stale`.
  - `GET /api/v2/db` shows both timestamps and `newer_available`.
  - The real ghcr.io download test moves into P3-9 and runs now, before Phase 4.
  - Open: `SCANNER_DB_RETRY_INTERVAL` is referenced but not yet defined (no default); asked the owner, to be added in P4-1.
- 2026-10-15 (owner, fourth round): update loop and DB age (DEMAND v0.6, 7.4 and 11).
  - No downgrade guard: install what the first answering source offers. A mirror a few hours behind is accepted. (No guard or "behind" class had been built; nothing to remove.)
  - Loop per source in order: pre-check, upstream check, then download and install if the digest differs. Stop on an equal digest or after an install. A failed source is recorded with its class and the loop continues. No source answered: mode `degraded`, one ERROR log, old DB kept. Return the mode, the active source and the per-source results. `last_upstream_check_at` is updated when at least one source answered.
  - `SCANNER_DB_AGE_WARN` (default `7d`): after each check, WARN with the age and the active source when the installed DB's `UpdatedAt` is older. `db_age` goes into `GET /api/v2/db` (P9-6) and the health output (P10-1). Visibility only.
  - Freshness is relative to the first source that answered; DB age is reported separately.
  - Implementation order: P3-8 (metadata.json) before P3-6, because the age WARN needs `UpdatedAt`.
- 2026-10-15 (owner): seed DB location. `SCANNER_DB_SEED_DIR` and `SCANNER_JAVA_DB_SEED_DIR`, defaults `/home/scanner/seed/db` and `/home/scanner/seed/java-db`. A missing seed directory means no seed, and readiness then waits for the first download. Chosen from: env var with image default, fixed path, or seed required at startup. DEMAND section 11 updated.
- 2026-10-15 (P3-4): DB swap mechanism. `<cache-dir>/db` (the path Trivy reads with `--cache-dir`) is a relative symlink to `<cache-dir>/db-versions/<version>`; a new version is activated by renaming a new symlink over it (atomic). The current and previous versions are kept; older ones and failed-download leftovers are removed at install time. Scans that opened the DB file keep reading it even after its directory is deleted (Linux keeps open files). `java-db` works the same. Each version stores its manifest digest in a `manifest-digest` file. A real `db` directory from the old layout or a seed is moved into `db-versions` once; during that one move there is a moment with no `db` path.
- 2026-10-15 (P3-1): OCI client is raw `net/http` (not go-containerregistry). Reasons: the manifest and token code already existed and runs over our route (`Dial` + `dialTLS`), and we need exact control of redirects (token never sent to another host:port), stall timeouts (P3-3) and timings. A library would add its own retries and redirect handling.
- 2026-10-15 (owner, third round):
  - TLS stage purpose: only to see whether the network path interferes with the TLS handshake, not certificate security. Normal verification against the system CA pool stays. No CA file option, no pinning, no insecure-skip-verify. (No CA option was ever added; nothing to undo.)
  - P2-8 added: classify pre-check failures and record the class in the result and the log.
  - Accepted limit: the direct route tries only the first resolved address. The owner runs the DNS, and the source pool already provides fallback. Not a task.
  - No DNS pool in code. DNS servers are set with Docker's `dns:` setting or `/etc/resolv.conf`, which Go's resolver tries in order; this goes into the v2 config README (P11-4).
  - The odd local timings (connect about 0.3ms) are expected on this network; no note in P11-1.
- 2026-10-15 (owner): pre-check DNS stage. Direct route: resolve the registry host. Proxy route (HTTP CONNECT or SOCKS5): record the DNS stage as skipped; the connect stage covers the proxy's DNS and TCP. Chosen from three options (resolve first hop, always resolve registry, skip). DEMAND 7.3 item 6 added.
- 2026-10-15 (P0-3): package layout confirmed as in PLAN.md: `pkg/v2/config`, `pkg/v2/dbmgr`, `pkg/v2/registry`, `pkg/v2/store`, `pkg/v2/runner`, `pkg/v2/queue`, `pkg/v2/api`, `pkg/v2/health`. Reason: no clashes with existing packages (`pkg/queue` vs `pkg/v2/queue` differ by path; import with an alias where both are used). Wiring: `cmd/scanner-trivy/main.go` is the one upstream file we must touch. When `SCANNER_V2_API_ENABLED=true` it wraps the existing v1 handler in a small `http.ServeMux` that sends `/api/v2/` to the v2 handler and everything else to the v1 handler, so `pkg/http/api/v1` stays unchanged. The v2 router uses gorilla/mux like v1. Readiness for Mongo and DB (P10-2) will need a touch to `/probe/ready` in `pkg/http/api/v1/handler.go`; decide the smallest hook when we get there.
- 2026-10-15 (P0-4): libraries and Mongo test strategy.
  - Mongo driver: official `go.mongodb.org/mongo-driver/v2` (includes GridFS). The only new module dependency for Mongo.
  - SOCKS5: `golang.org/x/net/proxy` (already in go.mod through `golang.org/x/net`; no new module). HTTP proxy: standard library `http.Transport.Proxy` / CONNECT.
  - OCI client: raw `net/http` (decided in P3-1, as recommended by PLAN).
  - Unit tests use fakes behind interfaces and never need Mongo.
  - Mongo integration tests copy the existing Redis pattern: build tag `integration`, `testcontainers-go` `GenericContainer` with image `mongo:7`, under `test/integration/...` or a `_test.go` with the tag next to `pkg/v2/store`. No testcontainers Mongo module (avoids a new dependency). Run with `make test-integration` (needs Docker).
- 2026-10-14: Digest store collection declined by the owner for now (hard to implement); the last scan of a digest is found through the `scans` collection. Multi-architecture handling and queue priorities are deferred. (See DEMAND section 14.)

## Upstream files touched

List every file from the original upstream repo that we modify, with the reason.

Touched before this plan started (commits `0c87038` "some modifyins" and `f917cc0` "smoke", on top of upstream `2691434`):

- `Dockerfile`: multi-stage build that compiles the binary in the image; `GOPROXY` set to `package-mirror.liara.ir`, `GOSUMDB=off`; `GOTRACEBACK=all`.
- `Dockerfile.dev`: same `GOPROXY` and `GOSUMDB` settings.
- `pkg/trivy/model.go`: `ScanResult.Type`, `Report.Results`, and `Vulnerability.Target` / `Vulnerability.Type` (not serialized).
- `pkg/trivy/wrapper.go`: `parseJSONReport` copies Target and Type onto each vulnerability; logs the full Trivy report and every vulnerability at INFO (debug code).
- `pkg/scan/transformer.go`: Harbor `vendor_attributes` gets a `Trivy: {Target, Type}` entry for every vulnerability.
- `Vagrantfile`: trailing whitespace only.

Touched by this plan:

- `pkg/trivy/wrapper_test.go`, `pkg/scan/transformer_test.go`, `test/integration/api/rest_api_test.go` (P0-6): test expectations for `vendor_attributes.Trivy` (owner chose KEEP). Test-only. (Correction: missing from this list until P5-1.)
- `cmd/scanner-trivy/main.go` (P9-1): reads the v2 config; when `SCANNER_V2_API_ENABLED` is true, starts `pkg/v2/service`, routes `/api/v2/` to its handler in front of the v1 router (an `http.ServeMux`), and at shutdown calls `StopAccepting` before and `Stop` after the HTTP server's `Shutdown`. With v2 disabled the v1 handler is served exactly as before.
- `go.mod`, `go.sum` (P5-1): new dependency `go.mongodb.org/mongo-driver/v2 v2.9.1` and its indirect modules; minimum-version bumps it requires: `golang.org/x/crypto` 0.51.0 -> 0.53.0, `golang.org/x/sync` 0.20.0 -> 0.21.0, `golang.org/x/sys` 0.45.0 -> 0.46.0, `golang.org/x/text` 0.37.0 -> 0.39.0, `github.com/klauspost/compress` 1.17.4 -> 1.19.2 (all indirect). Upstream unit and integration tests pass with them.

## Changelog

### Entry template (copy for each task)

```
### YYYY-MM-DD HH:MM  P<phase>-<n>  <short title>
- Status: done | partial | blocked
- What changed: ...
- Files: ...
- Tests run: <command> -> <result> (or "not run: reason")
- Decisions / surprises: ...
- Next: <next task ID>
```

### 2026-10-17  P10-1  GET /api/v2/health
- Status: done
- What changed:
  - `pkg/v2/api/health.go`: `{status, instance_id, checks, dbs, queue, recent_scans, other_instances, other_instances_error?}`; 200 for ok/degraded, 503 for unhealthy. Checks: `ready` (unhealthy with the `NotReady` reasons), `workers` (unhealthy with none running), one per DB kind (degraded for degraded mode, `newer_available`, stale against `SCANNER_DB_MAX_AGE_DEFAULT`, or older than `SCANNER_DB_AGE_WARN`), `queue` (degraded when the oldest queued scan is older than `SCANNER_HEALTH_QUEUE_STUCK_AFTER` while workers run; left out while MongoDB is down), `recent_scans` (degraded above 50% failures with at least 10 of the last 20 scans). Details are fixed texts with numbers and durations only. `getDB` and health share `localDBViews` and `otherInstances`.
  - `pkg/v2/queue`: `Pool.Running()`; `Queue.Recent()` (in-memory window of this replica's last 20 completed or failed scans, recorded after the write succeeded; lease losses and releases do not count); `Queue.CachedStats` (Stats reused for 10s; P10-4 uses it too).
  - `SCANNER_HEALTH_QUEUE_STUCK_AFTER` (10m).
- Files: `pkg/v2/api/{health,health_test,db,handler}.go`, `pkg/v2/queue/{metrics,metrics_test,queue,worker}.go`, `pkg/v2/config/{config,config_test}.go`, `pkg/v2/service/service.go`, `test/integration/queue/metrics_test.go`, `test/integration/apiv2/fullstack_test.go`
- Tests run: `go test -short -race ./...` -> ok; queue and apiv2 integration -> ok. Cases: ok with queue figures; each degraded rule (degraded mode with a proxied source, newer available, stale, too old, stuck queue, 6 of 10 failed) gives 200 degraded on its own check and ok again when cleared, never with the proxy user or password in the body; 8 failures out of 9 scans stay ok; no workers -> 503 unhealthy; MongoDB down -> 503 unhealthy without queue figures, then ok again; no token -> 401; the recent window keeps the last 20; `CachedStats` returns the cached depth within 10s; full stack after one success and one failure: degraded (unreachable DB source), recent 1/1, one worker, no password or path in the body.
- Decisions / surprises: none.
- Next: P10-4

### 2026-10-17  P10-2  Readiness and liveness
- Status: done
- What changed: `api.Handler.NotReady()` lists why v2 is not ready: shutting down, MongoDB down (ping flag), schema not ready, no Trivy DB, no Java DB while `SCANNER_JAVA_DB_SOURCES` is set, trivy binary missing; degraded DB mode is not a reason. `ReadyProbe(next)` answers 503 `not_ready` with the reasons, otherwise asks v1's probe. New `service.Routes(v1)` builds the mux that `main.go` now uses: `/api/v2/` -> v2, `/probe/ready` -> v2 readiness then v1, everything else (liveness `/probe/healthy` included) -> v1 unchanged. `dbmgr.Updater.JavaDBInstalled()`. With v2 disabled `main.go` serves v1 alone as before.
- Files: `pkg/v2/api/{ready,ready_test,handler}.go`, `pkg/v2/service/{service,service_test}.go`, `pkg/v2/dbmgr/updater.go`, `cmd/scanner-trivy/main.go`, `test/integration/apiv2/fullstack_test.go`
- Tests run: `go test -short -race ./...` -> ok; apiv2 integration -> ok. Cases: ready without a token; degraded with newer available stays ready; each of the five conditions makes it 503 with one reason and ready again when it clears; no Java sources -> no Java DB needed; shutting down -> 503. Service with MongoDB unreachable: readiness 503, liveness and v1 routes answered by v1, v2 needs the token. Full stack: ready while the DB updater is degraded, 503 after `StopAccepting`.
- Decisions / surprises: none.
- Next: P10-1

### 2026-10-17  P9-1  too_many_requests for the in-flight cap
- Status: done (follow-up to P9-1, owner decision)
- What changed: the in-flight cap answers 429 with the new code `too_many_requests` and `Retry-After: 1`; `queue_full` is only used for a full queue.
- Files: `pkg/v2/api/{errors,middleware,middleware_test}.go`
- Tests run: `go test -short -race ./pkg/v2/api/` -> ok (`TestLimitInflight` checks the new code)
- Decisions / surprises: none.
- Next: P10-1

### 2026-10-17  P9-8  API tests: handlers with fakes and the full stack
- Status: partial (everything except the v1 component test run, which is blocked as in P9-1)
- What changed: handler unit tests (fakes for the registry, readiness and DB state) and the MongoDB-backed handler tests were added with each task (P9-1 to P9-7). New `test/integration/apiv2/fullstack_test.go` starts the real `service.Start` on mongo:7 with an `httptest` registry (HEAD with `Docker-Content-Digest`, 404 for unknown tags, plain http so the WARN path and `--insecure` are used), a seed DB (the configured source is unreachable, so the updater is degraded but a DB is installed), and a fake `trivy` script that writes the real Trivy 0.74.0 fixture, counts its runs, can block on a file and can fail. Cases:
  - POST -> queued -> scanning (blocked Trivy) -> done with timings and the digest; while scanning, a covered request gets 200 and an uncovered one 409; then a narrower request is a hit (critical only, `confirmed_at` renewed, Trivy not started: AC2), a new tag with the same digest is a copy hit without Trivy (AC5), `force` (AC4) and a broader severity (AC13) start Trivy again.
  - Eight concurrent POSTs for a new tag while another scan runs: exactly one 202 and one Trivy run for that tag; queue full -> 429.
  - A forced rescan that fails: GET shows `failed`, the class with its fixed message, the previous result, and no path from stderr.
  - No seed DB: once MongoDB is up, POST answers 503 `not_ready`; `GET /api/v2/db` still answers.
  - Whole stack: missing and wrong tokens 401, an unknown field 400, a 2 MiB body 413, an unknown tag 404 `image_not_found`.
  - Graceful shutdown: with a scan running, `StopAccepting` makes POST 503 `not_ready`; `Stop` returns within the grace plus a little, and the scan is back in `queued` with attempt 0 and no worker; the logs have the request lines and "scan released at shutdown", and contain neither the registry password nor the service token.
- Files: `test/integration/apiv2/{fullstack_test,main_test}.go`
- Tests run: `go vet ./...` and with tags -> ok; `go test -short -race ./...` -> ok; `go test -count=1 -tags=integration ./test/integration/...` -> ok (api v1, apiv2, redis, queue, store); `go test -count=3 -race -tags=integration ./test/integration/apiv2/` -> ok. `make test-component`: not run again (blocked, see Current state).
- Decisions / surprises: none.
- Next: rerun the component tests when unblocked; Phase 10

### 2026-10-17  P9-7  db block in responses
- Status: done
- What changed: no new code; the block was built with P9-2 (`Handler.dbBlock`), P9-3 (renewal stores `db.freshness` for the hit's `max_db_age`) and P8-7 (the worker stores the freshness from the on-demand refresh at scan start). This task adds the tests that pin the rules: stored `updated_at`, `confirmed_at` and `freshness` are returned unchanged (never recomputed on read), `last_upstream_check_at` is this instance's, and a tag without a result shows the local DB state with freshness against the request's `max_db_age` (or the default).
- Files: `pkg/v2/api/dbblock_test.go`, `test/integration/apiv2/dbblock_test.go`
- Tests run: `go test -short -race ./pkg/v2/api/` -> ok; `go test -count=1 -tags=integration -run TestDBBlock ./test/integration/apiv2/` -> ok. Cases: a stored `stale` stays `stale` on GET while the local DB is fresh; hits with `max_db_age` 30m and 3h answer and store `stale` and `ok` (local DB confirmed 1h ago); a first POST shows the local DB `updated_at`, no `confirmed_at`, and `stale` for 30m.
- Decisions / surprises: none.
- Next: P9-8

### 2026-10-17  P9-6  GET /api/v2/db
- Status: done
- What changed: `pkg/v2/api/db.go`: `{instance_id, dbs, other_instances, other_instances_error?}`. `dbs` is this instance's state per kind (`db`, plus `java-db` when Java sources are configured) from the in-memory `DBStateStore`, so it answers while MongoDB is down: kind, mode, version, `updated_at`, `downloaded_at`, `installed_at`, manifest digest, active source, `last_upstream_check_at`, `last_confirmed_current_at`, `newer_available`, `db_age` (and seconds), freshness against `SCANNER_DB_MAX_AGE_DEFAULT`, `last_sources` (source names are already credential-free, `config.DBSource.String`). Unknown times are left out. Other instances come from `DBStateStore.Others` (new: `db_state` documents of other instance ids), grouped by instance with `state_updated_at`; while MongoDB is down or the read fails, `other_instances_error` says so and the request still succeeds.
- Files: `pkg/v2/api/{db,db_test,handler}.go`, `pkg/v2/store/dbstate.go`, `pkg/v2/service/service.go`, `test/integration/apiv2/{main_test,db_test}.go`
- Tests run: `go test -short -race ./...` -> ok; apiv2 integration -> ok. Unit (MongoDB down): 200 with the error note; a proxy source with user and password shows neither; degraded with newer available -> stale; `db_age` about 5h; `java-db` listed when configured, with an empty source list; no token -> 401. Integration: another instance's two documents are listed under it, this instance's stored document is not repeated.
- Decisions / surprises: none.
- Next: P9-7

### 2026-10-17  P9-5  GET /api/v2/scans
- Status: done
- What changed:
  - `store.Scan.CreatedAt` (`created_at`): set when the tag's document is inserted (enqueue or copy hit), never changed by requeue, renewal or completion.
  - Schema version 4: indexes `result_digest`, `image_digest`, `customer_ids_created_at` (`customer_ids`, `created_at` desc, `_id` desc), `created_at` (`created_at` desc, `_id` desc); `image_digest_state_finished_at` and `customer_ids_finished_at` are no longer created (dev databases are recreated; nothing drops them automatically). The state filter uses the existing `state_queued_at`.
  - `store.ScanFilter`, `store.ListQuery` (an `$and` of the given filters; `digest` is an `$or` of `result.digest` and `image.digest`; `from`/`to` inclusive on `created_at`; the keyset condition `created_at < t or (created_at = t and _id < id)`), `store.ListSort` and `MongoScans.List` (projection without `result.report`).
  - `pkg/v2/api/list.go`: unknown query parameters, a bad state, limit outside 1-200, bad times and a bad cursor -> 400; one item more than the limit decides `next_cursor` (base64url JSON of the last item's `created_at` and `_id`). Items: scan_id, state, image (latest request), created_at, confirmed_at, customer fields, request_id, `result` (digest, scope, image types, summary, truncated, DB updated_at, freshness) and `error` (class + fixed message) for failed scans; never findings.
- Files: `pkg/v2/store/{models,models_test,schema,repositories_mongo}.go`, `pkg/v2/queue/{queue,cache}.go`, `pkg/v2/api/{list,list_test,handler}.go`, `pkg/v2/service/service.go`, `test/integration/store/schema_test.go`, `test/integration/apiv2/{main_test,list_test}.go`, `docs/direct-scan/DEMAND.md` (index keys)
- Tests run: `go test -short -race ./...` -> ok; store, queue and apiv2 integration -> ok. Cases: query parsing (all parameters, defaults, nine rejections); on mongo:7 every filter (customer, digest of the result and of the latest request on a moved tag, repository, name, state, a platform found in the image, request id, from, to, an empty value), newest first; no findings or report in items; seven tags paged by three while a new tag is inserted after every page: every original tag exactly once, in order; `explain` of the customer, digest and customer-with-cursor queries shows IXSCAN and no COLLSCAN.
- Decisions / surprises: the list indexes include `_id` after `created_at` so the keyset order is served by the index (owner listed "created_at"; to confirm). `GET /api/v2/scans` and `GET /api/v2/scans/{id}` need only MongoDB up (no DB or schema check).
- Next: P9-6

### 2026-10-17  P9-4  GET /api/v2/scans/{id}
- Status: done
- What changed: `pkg/v2/api/get.go`: an id that is not 64 lowercase hex -> 404 `{"state": "not_found"}` without echoing it; unknown -> 404 `{"scan_id", "state": "not_found"}`; MongoDB down -> 503 `store_unavailable`. `done` -> the result view (P9-3), by default for the full stored scope; optional `platforms` and `severity` query parameters (comma-separated, normalized like POST) filter it, and a filter outside the stored scope is 400. `queued`/`scanning` -> `{scan_id, state, image, db, previous?}` with `Retry-After: 2`; `failed` -> the same plus `error: {class, message}` with a fixed message per failure class (`failureMessages`; unknown classes "the scan failed"), never the stored detail. `previous` = `{confirmed_at, digest, summary}` of the last good result. `summaryFor` is shared with the result view. `normalizeOptions` now checks severities also without platforms.
- Files: `pkg/v2/api/{get,get_test,handler,view,validate}.go`, `test/integration/apiv2/get_test.go`
- Tests run: `go test -short -race ./...` -> ok; `go test -count=1 -race -tags=integration ./test/integration/apiv2/` -> ok. Unit: four malformed ids -> 404 without echo; a bad severity filter -> 400 before the store; MongoDB down -> 503; no token -> 401. Integration: unknown id -> 404; queued -> `Retry-After: 2`, no findings, no previous; done -> full scope, no `cached`, then a `JAR`/`critical` filter with the summary of jar only, and a filter outside the scope -> 400; a forced rescan shows `previous` while queued; after a failure (stored detail with a path and stderr) the response has the class and fixed message only, the previous block, and no findings.
- Decisions / surprises: the view also returns `customer_ids`, `customer_data` and `request_id` (the last request's), so GET shows who asked last; to confirm.
- Next: P9-5

### 2026-10-17  P9-3  Cache decision, renewal and copy hits
- Status: done
- What changed:
  - `pkg/v2/queue/cache.go`: `Want` and `Serves` (the result conditions of DEMAND 6: digest, scanned platform, Trivy version, stored scope covers the request, result DB >= installed DB; an unknown installed DB never serves). `Renew` (pipeline `findOneAndUpdate` on `_id` + not queued/scanning + `result.digest`: `confirmed_at = $$NOW`, `db.freshness`, customer fields, `last_request_id`, `requested_at`, `received_at`, state done, error cleared). `FindCopySource` (another `_id`, `result.digest`, the same conditions as a query, `confirmed_at` desc; the source may be active). `SaveCopy` (insert for a new tag, else a conditional update while not active; a race gives `store.ErrNotFound` = miss).
  - `pkg/v2/api`: after the active-scan check and unless `force`, `serveFromCache`: renewal of the tag's own result, else a copy from another tag (report loaded from the source and attached to this tag with `SaveWithReport`, so a large report gets its own new GridFS file and the tag's older file is deleted); a vanished source file -> one more lookup, then a miss; a concurrent change -> miss -> enqueue. `writeHit` logs "scan skipped (db unchanged)" and answers 200 with `cached` and `db_unchanged`. `view.go`: the result view filtered to the request (findings of the requested platforms and severities, summary summed from `summary_by_platform` over the requested platforms at every severity, `platforms_found`/`not_found`/`has_more_platforms` from `image_platform_types`, image digest of the result, timings, customer fields and `request_id`).
  - `store.MongoReports.Load` maps a missing GridFS file to `store.ErrNotFound`.
- Files: `pkg/v2/queue/{cache,cache_test,queue}.go`, `pkg/v2/api/{scans,view,view_test}.go`, `pkg/v2/store/reports.go`, `pkg/v2/store/storetest/storetest.go`, `test/integration/apiv2/{main_test,cache_test}.go`
- Tests run: `go test -short -race ./...` -> ok; `go test -count=1 -race -tags=integration ./test/integration/apiv2/` -> ok (all subtests listed with -v); store and queue integration -> ok. Cases: `Serves` (narrower request, older installed DB, and seven misses); the view (filtering, summary per requested platform, found/not found/more, empty lists not null); on mongo:7: a narrower request hits, renews `confirmed_at`, overwrites the customer fields and `last_request_id`, leaves the result alone, creates no document, and stores no `cached`/`db_unchanged`; a failed last attempt with a good result is served and marked done; misses for `force`, a broader severity, another platform and a newer installed DB (all 202); a broader severity rescans the union; a copy hit for a new tag with the same digest gets its own GridFS file, and a later rescan of the source does not change the copy; a copy from a source that is being rescanned; a deleted source file makes the request a miss (202).
- Decisions / surprises: the `result.digest` index is added with the other list indexes in P9-5 (schema version bump); the lookup works without it meanwhile.
- Next: P9-4

### 2026-10-17  P9-2  POST /api/v2/scans
- Status: done
- What changed:
  - `pkg/v2/api/validate.go`: `scanRequest` and `validate` (DEMAND 5.1): `request_id` pattern, `requested_at` RFC 3339 and at most 5 minutes ahead, image names by `registry.ValidateImage`, 1-100 `customer_ids` of 1-128 characters, `customer_data` an object of at most 64 KiB, platforms lowercased/deduplicated/sorted (1-20), severities uppercased/deduplicated/sorted (default CRITICAL, HIGH), `max_db_age` with `config.ParseDuration` between 1m and 30d (default `SCANNER_DB_MAX_AGE_DEFAULT`). `runner.MaxPlatforms` is 20.
  - `pkg/v2/api/scans.go`: `createScan` in the decided order: decode/validate (400) -> readiness (503: stopping or schema not ready or no DB -> `not_ready`, MongoDB down -> `store_unavailable`) -> resolve (registry errors mapped; unknown errors 500 `internal` with the detail only logged) -> read the tag's document -> active scan: covered and same digest -> 200 with its state (also with `force`, document untouched), else 409 `scan_in_progress` `Retry-After: 5` -> enqueue: 202 `{scan_id, state, db}`, 429 `queue_full` `Retry-After: 10`, 409 when a racing request queued other work first, 200 when it queued the same work. A POST extends its own write deadline and has its own timeout (two registry tries plus four MongoDB calls). The `db` block: stored values when the tag has a result, else this instance's DB state (freshness against the request's `max_db_age`).
  - `api.Deps` (queue, scans, reports, resolver, DB state, readiness and Trivy-version functions), wired in `pkg/v2/service`.
  - `store.Scan.ReceivedAt` (`received_at`), written on insert and requeue.
- Files: `pkg/v2/api/{handler,scans,scans_test,validate,validate_test,middleware_test}.go`, `pkg/v2/service/{service,service_test}.go`, `pkg/v2/store/{models,models_test}.go`, `pkg/v2/queue/queue.go`, `pkg/v2/runner/result.go`, `test/integration/apiv2/{main_test,post_test}.go`
- Tests run: `go test -short -race ./...` -> ok; `go test -count=1 -race -tags=integration ./test/integration/apiv2/` -> ok; queue and store integration -> ok. Unit: every validation rule (20 rejections, normalization, defaults, limits accepted at 20 platforms and 30d); 400s and 503s come before any registry call; shutting down -> 503; registry error mapping without internal detail or paths. Integration (mongo:7, fake registry): 202 with the db block and stored normalized fields; a covered request while queued, also with `force`, gets 200 and leaves the document unchanged; an uncovered platform, a lower severity and a moved tag get 409 with `Retry-After: 5`; queue full 429 with `Retry-After: 10` while a covered request still joins; ten concurrent POSTs on two replicas give one document and exactly one 202.
- Decisions / surprises: `make test-component` built the image (the build context had the P9-1 wiring) but failed before testing anything: Docker refused to create the test's `redis` container because a container with that name already exists (see Current state). Not a test failure of ours; not rerun.
- Next: P9-3

### 2026-10-17  P9-1  Router, auth, HTTP hygiene, wiring
- Status: partial (code done; the v1 component test run is pending, see the next entry)
- What changed:
  - `pkg/v2/config`: `SCANNER_V2_AUTH_TOKEN` must have at least 32 characters when v2 is enabled (the error never contains the token); `SCANNER_V2_MAX_INFLIGHT` (32); `SCANNER_V2_CACHE_DIR` (`/home/scanner/.cache/scanner-v2`). The fallback-interval and instance-id WARNs are logged only when v2 is enabled (the defaults still apply).
  - New `pkg/v2/api`: `Handler` with a gorilla/mux router behind a chain: request log (one line: method, route template, status, duration, request id; `X-Request-ID` accepted when valid, otherwise generated, always returned), bearer auth (SHA-256 hashes compared with `subtle.ConstantTimeCompare`, case-insensitive scheme, 401 `unauthorized` with `WWW-Authenticate: Bearer`, also for unknown routes), the in-flight cap for POSTs (429 `queue_full`, `Retry-After: 1`). `decodeJSON`: `application/json` only (415), `http.MaxBytesReader` 1 MiB (413), unknown fields and trailing data rejected (400). The error shape and codes of DEMAND 5.0; 404/405 use the same shape. `StopAccepting` for shutdown.
  - New `pkg/v2/service`: `Start` (store client + monitor -> DB state store -> updater -> Trivy check -> worker pool and reaper -> handler; MongoDB down is not an error) and `StopAccepting`/`Stop` (pool: stop claiming, grace, release -> reaper -> updater -> monitor -> MongoDB disconnect with a 10s deadline). The DBs live in `<SCANNER_V2_CACHE_DIR>/trivy`, the worker caches in `<SCANNER_V2_CACHE_DIR>/workers`. Workers claim only while MongoDB is ready, a DB is installed and Trivy was found.
  - `dbmgr.Updater.DBInstalled()`.
  - `cmd/scanner-trivy/main.go`: see "Upstream files touched".
  - Server timeouts: the upstream server sets read, write and idle timeouts from `SCANNER_API_SERVER_*`; Go uses the read timeout as the header timeout when none is set, so `server.go` is not touched.
- Files: `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`, `pkg/v2/api/{handler,errors,middleware,middleware_test}.go`, `pkg/v2/service/{service,service_test}.go`, `pkg/v2/dbmgr/updater.go`, `cmd/scanner-trivy/main.go`
- Tests run: `go test -short -race ./...` -> ok; `go vet ./...` -> ok. New cases: auth (missing, wrong, wrong scheme, no scheme, prefix of the token, lowercase scheme, unknown route, token not in logs); the request log line (route template, status, request id, no body), invalid X-Request-ID replaced; the in-flight cap (third POST 429 with `Retry-After: 1`, GETs not limited); decoding (unknown field, trailing data, not JSON, wrong type, oversized 413, wrong content type 415, charset accepted); config (no WARNs when disabled, token missing/short, not checked when disabled, max in-flight 0); the service starts with MongoDB unreachable and no Trivy, answers 401 without a token, and stops within the test deadline. `make test-component`: running (image build), result in the next entry.
- Decisions / surprises: see Decisions 2026-10-17 (complete Phase 9).
- Next: P9-2

### 2026-10-17  P8-7  One scan document per image tag
- Status: done
- What changed:
  - `pkg/v2/store/models.go`: `ScanID(image)`; `Scan` reorganized: request fields with `LastRequestID`, the current attempt (state, options, reference, timings, queue fields, error), and the last successful scan in `Result *ScanResult` plus `DB *ScanDB` and `ConfirmedAt`. `TrivyInfo`, `RequestID`, `PriorRequestID`, `ActiveKey`, top-level `ScannedPlatform`, `Platforms`, `PlatformsFound/NotFound`, `HasMorePlatforms`, `Summary`, `Truncated`, `Report`, `ReportGridFSID` removed.
  - `pkg/v2/store`: `ScanRepository` keeps `Create` and `Get` (`GetByRequestID`, `LastDone`, `ErrDuplicateRequestID` removed; the cache queries come with P9-3). Schema version 3 without `request_id_unique` and `active_key_unique`. `ReportStore`: reports live on `scan.Result`; `Attach` copies the result (no aliasing through the pointer) and no longer deletes earlier files; new `DiscardOthers`; `SaveWithReport` deletes the document's other files after a successful save.
  - `pkg/v2/runner`: `Scan` fills `Result` (scanned digest and scope, scanned platform, Trivy version, image platform types, summary, new `SummaryByPlatform`) and `DB`; `parseResult` counts per platform.
  - `pkg/v2/queue`: `Enqueue` inserts the tag's document or requeues it with a `findOneAndUpdate` filtered on state not queued/scanning (up to 3 decisions when racing); `ErrScanInProgress`; `Covers` (exported for P9-3) and scope union; `ActiveKey` removed. `Complete` sets `result`, `db`, `confirmed_at` (`$$NOW`); `Fail` and the reaper keep the result. The pool stores the freshness from the on-demand refresh on `db.freshness`. Claim, leases, fencing, reaper, `Release` and shutdown unchanged.
- Files: `pkg/v2/store/{models,models_test,repository,repositories_mongo,memory,reports,schema}.go`, `pkg/v2/store/storetest/storetest.go`, `pkg/v2/runner/{result,result_test,scan,scan_test,manual_test}.go`, `pkg/v2/queue/{queue,lease,reaper,worker}.go`, `test/integration/store/{mongo,repositories,schema}_test.go`, `test/integration/queue/{enqueue,lease,pool,reaper,shutdown,tag}_test.go`
- Tests run: `go vet ./...` and with tags integration and manual -> ok; `go test -short -race ./...` -> ok; `go test -race -count=2 -tags=integration ./test/integration/queue/ ./test/integration/store/` -> ok. New cases on mongo:7: first scan creates the tag document (id = `ScanID`); while queued, a covered request joins and another digest/platform/severity gets `scan_in_progress` (also while scanning); ten concurrent requests for one tag on three replica clients create one document and one claimable scan; queue full refuses a new tag but a covered request joins; rescan of the same digest widens to the union, keeps the result, clears the old error, overwrites the request fields; a moved tag uses the request's scope and keeps the old result; through the pool with GridFS: the same tag scanned twice keeps one document and one (new) file, a failed rescan keeps the last good result and its file, the scanner gets the union scope. All earlier queue tests (claim, lease, fencing, reaper, release, shutdown, metrics) pass on the new identity. `TestManualScan` compiles; not run again (needs Docker Hub and a DB).
- Decisions / surprises: see Decisions 2026-10-17. Cache hits (renewal, copy across tags) and their tests are P9-3; the auth token rules are P9-1.
- Next: P9-1 (after the owner resends the Phase 9 message)

### 2026-10-17  P8-6  Queue tests on real MongoDB
- Status: done
- What changed: the owner's test list, on mongo:7 with separate `store.Client`s acting as replicas, maps to:
  - claimed exactly once under contention: `TestClaim` (4 replicas x 4 workers, 40 scans);
  - ten concurrent identical requests give one scan: `TestEnqueue`, now spread over 3 replica clients (also the same request_id case);
  - killed worker -> lease expires -> requeued -> finished by another worker: `TestReap`;
  - a stale worker's late completion is rejected: `TestFencedWrites`, and the pool's lost-lease case in `TestPool`;
  - poison job -> `failed` / `worker_lost` after max attempts: `TestReap`;
  - queue full: `TestEnqueue` (`ErrQueueFull`); the 429 with Retry-After is the API's job (P9);
  - graceful shutdown releases the lease: `TestShutdown`, the hand-off now to a pool on another client;
  - retry after a failed scan with the same request_id creates a new scan: `TestFencedWrites` and `TestReap`;
  - no claim while not ready: `TestPool`.
  - `mongotest.StartContainer` sets the container's `nofile` limit to 64000. With Docker's default 1024, `-count=3` runs (one database per test) made MongoDB abort with "Too many open files" (WiredTiger panic, exit 14), failing every later test.
- Files: `test/integration/queue/enqueue_test.go`, `test/integration/queue/shutdown_test.go`, `test/integration/mongotest/mongotest.go`
- Tests run: `go test -race -count=3 -tags=integration ./test/integration/queue/ ./test/integration/store/` -> ok; `go test -count=1 -tags=integration ./test/integration/...` -> ok; `go test -short -race ./...` -> ok; `go mod tidy` leaves `go.mod` unchanged (uses the `container.Ulimit` alias, no new direct import).
- Decisions / surprises: MongoDB in production also needs a high `nofile` limit (MongoDB advises 64000); to add to the compose file and README in P11.
- Next: P9-1

### 2026-10-17  P8-5  Queue metrics
- Status: done
- What changed: `pkg/v2/queue/metrics.go`: `Queue.Stats(ctx)` returns `Stats`:
  - `Depth` and `OldestQueuedAge` from one aggregation on queued scans (`$sum`, `$min` of `queued_at`, age = `$$NOW - oldest`, so on MongoDB's clock); 0 when nothing is queued. Same value on every replica.
  - Per-replica counters: `Claims` and `ClaimDuration` (number and total duration of `Claim` calls, including empty ones; latency = duration / claims, a Prometheus summary in P10-4), `LeaseLosses`, `ReaperRequeues`.
  - `Claim` in `lease.go` now times itself.
- Files: `pkg/v2/queue/metrics.go`, `pkg/v2/queue/lease.go`, `test/integration/queue/metrics_test.go`, `test/integration/queue/pool_test.go`
- Tests run: `go test -race -count=1 -tags=integration ./test/integration/queue/` -> ok; `go build ./...` -> ok. Cases: empty queue gives 0/0; two queued scans, the oldest set ten minutes back, give depth 2 and age about 10m; a claim lowers the depth and counts one timed claim; a reaped scan counts one requeue; the pool's lost-lease test counts one lease loss.
- Decisions / surprises: claim latency is the duration of the claim call (owner); the wait in the queue is already stored per scan as `queue_wait_ms`. Exposing these on `/metrics` is P10-4.
- Next: P8-6

### 2026-10-17  P8-4  Graceful shutdown
- Status: done
- What changed:
  - `Queue.Release(ctx, scan)` in `pkg/v2/queue/lease.go`: a fenced write that puts a claimed scan back to `queued` with `attempt - 1` (the attempt is not counted) and removes `worker`, `lease_until` and `started_at`. `request_id` and `active_key` stay, so it is still the active scan of its work.
  - `Pool` in `pkg/v2/queue/worker.go`: running scans now derive their context from a pool-wide jobs context instead of `context.Background()`. When `Run`'s context ends (SIGTERM), the workers stop claiming at once; `Run` waits up to `SCANNER_SHUTDOWN_GRACE` for running scans; after that it logs a WARN and cancels the jobs context, which kills Trivy (process group, P7-2). A scan killed that way is released instead of failed or completed. `Run` returns when every worker has stopped.
- Files: `pkg/v2/queue/lease.go`, `pkg/v2/queue/worker.go`, `test/integration/queue/shutdown_test.go`
- Tests run: `go test -race -count=1 -tags=integration ./test/integration/queue/` -> ok; `go test -short -race ./pkg/v2/...` -> ok. Cases (grace 1s): a scan that ends within the grace is completed and `Run` returns before the grace is over; a scan still running at the end of the grace is killed, is back in `queued` with attempt 0, keeps `request_id` and `active_key`, has no worker/lease/started/failure fields, `Run` returns between 1s and 3s, and another pool then finishes it with attempt 1; no scan is claimed after shutdown starts.
- Decisions / surprises: a scan that happens to finish just as the grace ends is released, not completed; it is scanned again by another replica. Compose `stop_grace_period` must be longer than `SCANNER_SHUTDOWN_GRACE` (P11-1).
- Next: P8-5

### 2026-10-17  P8-3  Reaper
- Status: done
- What changed: `pkg/v2/queue/reaper.go`:
  - `Reap(ctx)` runs two `UpdateMany` calls on scans in `scanning` whose `lease_until` is before MongoDB's `$$NOW` (`$expr`). First, those with `attempt >= SCANNER_QUEUE_MAX_ATTEMPTS` become `failed`, class `worker_lost`, with `finished_at`, `total_ms` and `prior_request_id`; `request_id`, `active_key` and `lease_until` are removed. Then the others go back to `queued` (worker, `lease_until` and `started_at` removed; `active_key` kept, so they stay the active scan of their work).
  - It returns (requeued, failed), counts requeues in the metrics and logs a WARN when it recovered anything.
  - `RunReaper(ctx, interval)` runs it every interval (`ReapInterval` = 30s in production) and skips rounds while MongoDB is not ready.
- Files: `pkg/v2/queue/reaper.go`, `pkg/v2/queue/metrics.go`, `test/integration/queue/reaper_test.go`
- Tests run: `go test -race -tags=integration -run TestReap ./test/integration/queue/` -> ok (twice on 2026-10-15, again on 2026-10-17). Cases: a scan whose lease is valid is left alone; a scan claimed by a "dead" worker (no heartbeat, 200ms lease) is requeued by another replica, keeps its active key, and is finished by that replica's pool with attempt 2; a poison job with max attempts 2 fails with `worker_lost` after the second expiry, gives up its `request_id` and active key, is not claimed again, and a retry with the same `request_id` creates a new scan; `RunReaper` with a 100ms interval requeues an expired scan once the client's monitor reports MongoDB ready.
- Decisions / surprises: Correction: the code and tests were committed by the owner as `acc55d1` (" Phase: 8 (queue)") before this documentation; this entry records them.
- Next: P8-4

### 2026-10-15  P8-2  Claims, leases, fenced writes, worker pool
- Status: done
- What changed:
  - `pkg/v2/queue/lease.go`, all on MongoDB's clock with pipeline updates:
    - `Claim(ctx, worker)` = `findOneAndUpdate` on `state: queued`, sorted by `queued_at`, setting `scanning`, worker, `attempt + 1`, `started_at = $$NOW`, `lease_until = $$NOW + lease`; `ErrNoJob` when empty.
    - `Heartbeat`, `Complete` and `Fail` are `UpdateOne` calls filtered on `_id` + `worker` + `attempt` + `state: scanning`; no match = `ErrLeaseLost`. Every value written goes inside `$literal`, because pipeline updates read strings starting with `$` as field paths.
    - `Complete` sets the result (report or GridFS id), `finished_at`, `queue_wait_ms = started_at - queued_at`, `total_ms = $$NOW - queued_at`, and removes `active_key` and `lease_until`.
    - `Fail` sets `failure_class`, `error` and `prior_request_id = $request_id`, and removes `request_id`, `active_key` and `lease_until`.
  - `pkg/v2/queue/worker.go`: `Pool` with `Scanner` (runner) and `Refresher` (updater) interfaces, a `ready` function (MongoDB ready and a DB installed; no claim otherwise) and the replica name.
    - `Run` starts `SCANNER_QUEUE_WORKERS` workers named `<replica>/worker-<n>`. They claim, or wait for the poll interval plus up to 50% jitter, or until an enqueue in the replica wakes them.
    - `process` heartbeats every third of the lease; a lost lease cancels the job context (the runner then kills Trivy's process group) and discards the result.
    - It calls `RefreshForScan` with the request's `max_db_age` (or `SCANNER_DB_MAX_AGE_DEFAULT`), then `Scan`. A `ScanError` gives `Fail` with its class (else `internal_error`); success gives `store.SaveWithReport` with `Complete`.
    - Completion and failure writes are retried with growing pauses (1s up to 15s) for up to 2 minutes, then an ERROR log with the `scan_id`.
  - Lease losses are counted (`metrics.go`, completed in P8-5).
- Files: `pkg/v2/queue/lease.go`, `pkg/v2/queue/worker.go`, `pkg/v2/queue/metrics.go`, `test/integration/queue/lease_test.go`, `test/integration/queue/pool_test.go`, `test/integration/queue/enqueue_test.go`
- Tests run: `go test -race -count=3 -tags=integration ./test/integration/queue/` -> ok; `go test -short -race ./pkg/v2/...` -> ok; `make test` -> ok. Integration (`mongo:7`):
  - 40 scans claimed by 4 replicas (4 clients) x 4 goroutines: each exactly once;
  - the oldest first, attempt 1, `lease_until` = MongoDB's now + 60s;
  - a heartbeat extends the lease, a wrong attempt is `ErrLeaseLost`;
  - after a requeue, the stale worker's `Complete` and `Fail` are rejected and the current worker's result is stored;
  - values starting with `$` are stored literally, `active_key` and `lease_until` are removed, timings are set, a done scan keeps its `request_id`;
  - a failed scan moves `request_id` to `prior_request_id` and a retry with the same `request_id` creates a new scan.
  - Pool with fake scanner and refresher: two scans done, with the refresh given the request's `max_db_age` and the default; a `ScanError` ends `failed` with its class; no claim while not ready, then done once ready; with a 1h poll interval an enqueue is picked up at once; a lease taken over by another replica cancels the running scan and nothing is written.
- Decisions / surprises: the test helper first created queues with 0 workers (the pool ran nothing); fixed. The completion retry window is a `Pool` field so it stays 2 minutes in production.
- Next: P8-3

### 2026-10-15  P8-1  Enqueue, dedupe, idempotency
- Status: done
- What changed:
  - New package `pkg/v2/queue`:
    - `New(client, cfg)`.
    - `ActiveKey(scan)` = sha256 of digest, sorted platforms, sorted severities, scanned platform and Trivy version.
    - `Enqueue(ctx, scan)` returns `(scan, created, err)`: an existing scan with the same `request_id` (queued, scanning or done) is returned; then a queued or scanning scan with the same `active_key`; then `ErrQueueFull` if `queued` count >= `SCANNER_QUEUE_MAX_LENGTH`; otherwise insert with `state: queued`, `attempt: 0`, `queued_at` (the replica's clock; only lease times use MongoDB's clock). A duplicate-key error on the insert (a concurrent request won) returns the winner's scan, found by `request_id` or `active_key`. A successful enqueue wakes an idle worker of this replica.
  - Model: `reference`, `attempt`, `active_key`, `prior_request_id`, reserved `priority`, `options.max_db_age`.
  - Schema version 2: indexes `active_key_unique` (unique, partial on `{active_key: {$type: "string"}}`) and `state_lease_until` (for the reaper).
  - Config `QueueLease` (60s), `QueueMaxAttempts` (3), `QueuePollInterval` (2s), `ShutdownGrace` (30s).
  - Test helper package `test/integration/mongotest` (`StartContainer` for `TestMain`, `Config` with a new database per test, `Client` with the schema ensured).
- Files: `pkg/v2/queue/queue.go`, `pkg/v2/queue/metrics.go` (placeholder for P8-5), `pkg/v2/store/models.go`, `pkg/v2/store/schema.go`, `pkg/v2/store/*_test.go`, `pkg/v2/config/*`, `test/integration/mongotest/mongotest.go`, `test/integration/queue/enqueue_test.go`, `test/integration/store/schema_test.go`
- Tests run: `make test` -> ok; `go test -tags=integration ./test/integration/...` -> ok. Integration cases (`mongo:7`):
  - a new scan is queued with its active key and no `priority`;
  - the same `request_id` returns the first scan;
  - identical work shares one scan whatever the list order;
  - each of digest, platforms, severities, scanned platform and Trivy version makes new work;
  - ten concurrent identical requests give one scan and one document;
  - ten concurrent requests with the same `request_id` give one document;
  - with a full queue new work gets `ErrQueueFull` while identical work still joins;
  - a done scan stays idempotent and identical work after it is a new scan.
- Decisions / surprises: the retry-after-failure case (`prior_request_id`) is tested with the real failure write in P8-2.
- Next: P8-2

### 2026-10-15  P7-8  Trivy 0.74.0 and the scan platform
- Status: done
- What changed:
  - Trivy 0.74.0 (the Dockerfile pin) is the target. Checked with the binary copied out of `aquasec/trivy:0.74.0`, against a DB installed by `TestManualUpdate`:
    - The help still has `--image-src` (default `docker,containerd,podman,remote`), `--skip-version-check`, `--list-all-pkgs` (default true), `--platform`, `--insecure` and `TRIVY_PASSWORD`.
    - node:22-alpine3.20 scans fine. A `pip` result without findings still appears with `--list-all-pkgs=false`.
    - eclipse-temurin:21-jre-alpine without a Java DB still fails with "Unable to initialize the Java DB: Java DB update failed: '--skip-java-db-update' cannot be specified on the first run".
    - A missing platform gives "remote error: no child with platform windows/amd64 in index alpine:3.22"; a missing image gives "MANIFEST_UNKNOWN" instead, so the platform case can be told apart.
  - The fixture `testdata/node-alpine.json` was regenerated from 0.74.0 output (same trimming). Its top-level, result and vulnerability fields are identical to the 0.71.2 fixture, and the same severities were picked.
  - Config `ScanPlatform` (`SCANNER_SCAN_PLATFORM`, default `linux/amd64`, must be `os/arch[/variant]`, else a startup error). The runner passes `--platform`, classifies "no child with platform" as `platform_not_found`, and sets `store.Scan.ScannedPlatform` (`scanned_platform`). The fake trivy reports 0.74.0.
- Files: `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`, `pkg/v2/runner/trivy.go`, `pkg/v2/runner/scan.go`, `pkg/v2/runner/*_test.go`, `pkg/v2/runner/testdata/node-alpine.json`, `pkg/v2/store/models.go`, `pkg/v2/store/models_test.go`
- Tests run: `go test -short -race -count=2 ./pkg/v2/...` -> ok; `make test` -> ok; integration `./test/integration/store/` -> ok. New cases: `--platform linux/amd64` in the argument list, `platform_not_found` from the fake trivy, `scanned_platform` on the scan, bad `SCANNER_SCAN_PLATFORM`. Manual run with 0.74.0 through our runner: node:22-alpine3.20 in 11.0s with the same result as 0.71.2 (critical 5, high 53, 58 findings, `jar` not found); eclipse-temurin `java_db_missing` in 12.2s.
- Decisions / surprises: none; 0.74.0 behaves like 0.71.2 for everything we use. The cache rule (a different Trivy version is a cache miss) is applied in the cache decision (P9-3) and the dedupe key (P8-1).
- Next: P8-1

### 2026-10-15  P7-7  Scan runner tests and a real-image run
- Status: done (Phase 7 complete)
- What changed: `pkg/v2/runner/manual_test.go` (build tag `manual`): `TestManualScan` resolves `MANUAL_IMAGE` with the real registry client (default Docker Hub) and scans the `@digest` reference with the real Trivy, using a DB installed in our layout by `TestManualUpdate`. The command is in `CLAUDE.md` section 4. The automated part of P7-7 (fixtures from real output, fake trivy for the env allowlist, the timeout kill with children, huge output, exit codes, stderr redaction, the DB swap during a scan, two concurrent Trivy processes) was written with P7-1 to P7-6.
- Files: `pkg/v2/runner/manual_test.go`, `CLAUDE.md`
- Tests run: `go test -short -race -count=2 ./pkg/v2/...` -> ok; `make test` -> ok; `go test -tags=integration ./test/integration/...` -> ok. Manual, on this machine (2026-10-15):
  - DB installed by `TestManualUpdate` in 19.6s.
  - `library/node:22-alpine3.20` resolved to `registry-1.docker.io/library/node@sha256:2289fb1f...` (an OCI image index). Scanned in 9.8s (trivy 9.784s, parse 3ms): image platforms `[alpine node-pkg]`, requested `jar` reported in `platforms_not_found`, summary critical 5, high 53, medium 31, low 22, 58 findings stored, not truncated. Log lines as specified, no findings in them.
  - `library/eclipse-temurin:21-jre-alpine` (contains jars), no Java DB installed: failed as `java_db_missing` after 11.9s with Trivy's "Unable to initialize the Java DB: ... '--skip-java-db-update' cannot be specified on the first run" in the redacted stderr tail.
- Decisions / surprises: when the tag points to an image index (both images above), the stored digest is the index digest and Trivy picks the platform matching the host (linux/amd64 here). This is the deferred multi-architecture question (DEMAND section 14), now visible. The scratch DB (1.6 GB) was deleted after the run.
- Next: P8-1

### 2026-10-15  P7-4, P7-5, P7-6  Scan orchestration
- Status: done
- What changed: `pkg/v2/runner/scan.go`:
  - `Runner.Scan(ctx, worker, scan, reference)`:
    1. Runs Trivy (`runTrivy`, which now logs "triggering scan" with scan_id, digest, customer_ids, platforms, severities, trivy_version, db_updated_at and db_manifest_digest once the DB version is pinned).
    2. Parses and removes the output.
    3. Records every image type with `PlatformRepository.Seen` (a failure there is logged, the scan goes on).
    4. Fills `Trivy` (version, DB UpdatedAt, manifest digest), `Platforms`, `PlatformsFound`, `PlatformsNotFound`, `HasMorePlatforms`, `Summary`, `Truncated` and `ScanMS`.
    5. Returns the report `{"findings": [...]}` for `store.SaveWithReport`.
    6. Logs "scan done" (scan, trivy and parse ms, summary, findings stored, truncated, platforms found / not found; never the findings) or WARN "scan failed" with the failure class.
  - `CheckTrivy` runs `trivy --version` (30s limit, same env allowlist) and keeps the version; `Version()` and `Ready()` (false while Trivy is missing or failing).
  - `NewRunner` takes the `PlatformRepository`. `store.Scan` has `platforms_found`, `platforms_not_found`, `truncated` and `failure_class`.
  - The queue sets the state and the other timings (P8).
- Files: `pkg/v2/runner/scan.go`, `pkg/v2/runner/scan_test.go`, `pkg/v2/runner/trivy.go`, `pkg/v2/runner/trivy_test.go`, `pkg/v2/store/models.go`, `pkg/v2/store/models_test.go`
- Tests run: `go test -short -race -count=3 ./pkg/v2/...` -> ok; `make test` -> ok; integration `./test/integration/store/` -> ok. The fake trivy answers `--version` and can replay the fixture.
  - Scan on the fixture: Trivy and DB info, platforms (npm requested and not in the image goes to `platforms_not_found`), summary, 3 findings, all 3 image types recorded with the digest, no output file left.
  - Logs: the exact "triggering scan" fields, "scan done", no finding id, no password.
  - The report through `SaveWithReport`: inline with the default limit, GridFS with a limit of 100, loaded back with the finding field names.
  - A Trivy failure: classified, WARN "scan failed", nothing recorded.
  - Invalid output: classified, file removed.
  - `CheckTrivy`: version found, version command failing, binary missing.
- Decisions / surprises: one commit for P7-4 (upsert), P7-5 and P7-6, because they are one function.
- Next: P7-7

### 2026-10-15  P7-2, P7-3 (and the discovery part of P7-4)  Parsing Trivy output
- Status: done (P7-4 partial: the upsert into `platforms` comes with P7-5)
- What changed: `pkg/v2/runner/result.go`:
  - `ValidateOptions(platforms, severities)`: platforms required, at most `MaxPlatforms` (50), each `^[a-z0-9_-]{1,64}$`; severities from `Severities` (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL, uppercase); errors wrap `ErrInvalidOptions` (400 in P9-2).
  - `parseResult(output, platforms, severities, maxFindings)` reads the JSON with a streaming decoder, one result at a time (other top-level values are skipped). For results whose type (lowercased) is requested: `Summary` counts every severity (all five keys, lowercase); `Findings` keep only the requested severities, with the stored fields (id, package, installed and fixed version, severity, title, primary URL, status, target, type), at most `maxFindings`, then `Truncated`. Across all results: `ImagePlatforms` (sorted), `PlatformsFound` / `PlatformsNotFound` for the requested ones, `HasMorePlatforms`. A `SchemaVersion` other than 2 or malformed JSON is `output_invalid`.
- Files: `pkg/v2/runner/result.go`, `pkg/v2/runner/result_test.go`, `pkg/v2/runner/testdata/node-alpine.json` (real Trivy 0.71.2 output for node:22-alpine3.20, trimmed to a few vulnerabilities per result plus a real `pip` result without findings; descriptions kept)
- Tests run: `go test -short -race -count=3 ./pkg/v2/runner/` -> ok. Cases: alpine with HIGH,CRITICAL (3 findings, full summary, found, has more); the first finding equals the fixture's fields and the fixture's description is not kept; requested `npm` not in the image is reported as not found, not clean; `pip` found with no findings; all types requested (no more platforms); limit 2 truncates while the counts stay complete; a capitalised type matches; 20000 results streamed; 7 kinds of invalid output; option validation (2 valid, 8 invalid).
- Decisions / surprises: one commit for P7-2 and P7-3 because parsing, filtering and counting are one pass over the results.
- Next: P7-5

### 2026-10-15  P7-1  Running Trivy
- Status: done
- What changed:
  - New package `pkg/v2/runner`: `NewRunner(cfg, trivyPath, cacheDir, workDir)`; `runTrivy(ctx, worker, reference)` returns the path of Trivy's JSON output (the caller removes it) and `DBInfo` (UpdatedAt, manifest digest).
    1. Gives the worker its own cache directory `<workDir>/<worker>` (0700).
    2. Pins the active DB version (`dbmgr.PinActiveVersion`; no DB gives `db_missing` without starting Trivy) and the Java DB version if there is one.
    3. Points the worker's `db` / `java-db` symlinks at those concrete version directories (atomic rename).
    4. Creates a 0600 output file.
    5. Runs `trivy image --scanners vuln --format json --output <file> --list-all-pkgs=false --skip-db-update --skip-java-db-update --skip-version-check --image-src remote --cache-dir <worker dir> --timeout <SCANNER_SCAN_TIMEOUT minus 10%, at most 30s less> --quiet [--insecure for http registries] <reference>`.
    6. Trivy runs in its own process group; at `SCANNER_SCAN_TIMEOUT`, `cmd.Cancel` kills the whole group (`WaitDelay` 5s).
    7. The environment is an allowlist: `PATH`, `HOME`, `TMPDIR`, `TRIVY_*`, the proxy variables; the parent's `TRIVY_USERNAME`/`TRIVY_PASSWORD` are replaced by the robot account.
    8. Only the last 8 KiB of stderr is kept, with the robot password replaced.
    9. Failure classes: hard kill or "context deadline exceeded" = `trivy_timeout`; "Unable to initialize the Java DB" = `java_db_missing`; other exits = `trivy_exit_error`; output above `SCANNER_SCAN_MAX_OUTPUT` = `output_too_large`; no output file = `output_invalid`. The output file is removed on every failure.
  - `dbmgr`: `PinActiveVersion(cacheDir, db)` with `ErrNoDB`. `InstallDB` (exported, was `installDB`) swaps and cleans up under the pin mutex and never removes a pinned version. `ReadMetadata` is exported.
  - Config `ScanMaxOutput` (`SCANNER_SCAN_MAX_OUTPUT`, bytes, 268435456) and `ScanMaxFindings` (`SCANNER_SCAN_MAX_FINDINGS`, 10000).
- Files: `pkg/v2/runner/trivy.go`, `pkg/v2/runner/trivy_test.go`, `pkg/v2/dbmgr/install.go`, `pkg/v2/dbmgr/install_test.go`, `pkg/v2/dbmgr/metadata.go` and renames in `pkg/v2/dbmgr/*`, `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race -count=10 ./pkg/v2/runner/ ./pkg/v2/dbmgr/` -> ok; `make test` -> ok. A fake `trivy` shell script driven by `TRIVY_FAKE_*` variables (they pass the allowlist):
  - success: exact argument list, 0600 output, DB info;
  - `--insecure` for a plain-http registry;
  - environment: no `SCANNER_*` variable and none of the Mongo URI, service token or other secrets; robot account in `TRIVY_USERNAME`/`TRIVY_PASSWORD` only, the parent's stale `TRIVY_PASSWORD` replaced, `HTTPS_PROXY` kept; credentials not in argv;
  - hard timeout (300ms) kills the script and its `sleep` child (checked with `kill -0`);
  - Trivy's own timeout message;
  - 2000 bytes against a limit of 1000;
  - exit status 2 with the password redacted in the stderr tail;
  - the Java DB message;
  - no DB installed (Trivy not started);
  - two installs during a running scan: the scan reads the same version at start and end, and the version is removed by the next install after the scan;
  - two workers run at the same time, each with its own cache directory.
  - `dbmgr`: pinned versions survive installs, two pins on one version.
- Decisions / surprises: pins live in memory, so they protect versions inside one scanner process; each instance has its own cache volume (DB state is per instance). Each worker keeps its own Trivy layer cache (`<workDir>/<worker>/fanal`), because Trivy's bolt cache cannot be shared by concurrent processes; disk for P11-4.
- Next: P7-2

### 2026-10-15  P1-4  Follow-up: duplicate DB sources
- Status: done
- What changed: `ParseDBSources` returns "source N: same repository and route as source M" when an entry repeats the repository and route of an earlier one (options do not count). The same repository through a different route is allowed (a fallback). The error never contains the route, which may hold proxy credentials. This also removes the duplicate `db_checks` id case noted in P5-6.
- Files: `pkg/v2/config/sources.go`, `pkg/v2/config/sources_test.go`
- Tests run: `go test -short -race -cover ./pkg/v2/...` -> ok (config 98.9%). Cases: a repeat with a different option is rejected, a repeated proxy route is rejected without its credentials in the error, the same repository through two routes is accepted.
- Decisions / surprises: none.
- Next: P7-1

### 2026-10-15  P6-3  Registry client tests
- Status: done (Phase 6 complete)
- What changed: `pkg/v2/registry/auth_test.go` adds the remaining cases of the owner's list; the fake Harbor can now set `expires_in`. The other items were covered in P6-1 (index vs plain manifest, missing digest header, invalid names) and P6-2 (404, 401/403, timeouts).
- Files: `pkg/v2/registry/auth_test.go`, `pkg/v2/registry/registry_test.go`
- Tests run: `go test -short -race -count=3 -cover ./pkg/v2/...` -> ok (registry 95.2%, oci 91.2%, dbmgr 90.1%, config 98.9%); `make test` -> ok; `go test -tags=integration ./test/integration/...` -> ok. New cases:
  - a token with `expires_in` 1 is reused within the second and fetched again after it;
  - tokens Harbor stops accepting (a restart) are replaced;
  - a registry that challenges forever gives `registry_auth_failed` after exactly `MaxChallenges+1` requests;
  - a manifest redirect to another host resolves and that host receives no `Authorization`;
  - `http://` gives exactly one WARN naming the host, https none;
  - redaction: 500, 403, a hanging registry, a refused robot password and a missing tag. No error and no log line contains the password, a token, `Basic `, `Bearer ` or `Authorization`.
- Decisions / surprises: none.
- Next: P7-1

### 2026-10-15  P6-2  Registry error mapping and retry
- Status: done
- What changed: in `pkg/v2/registry`, `ErrImageNotFound`, `ErrAuthFailed` and `ErrUnavailable` (with `ErrInvalidName`; the API maps them to 404, 502, 503 + retry hint and 400 in P9-2). `checkResponse` maps a refused token request (`oci.ErrTokenDenied`), 401 and 403 to auth failed; network errors, timeouts and 5xx to unavailable; 404 to not found; any other status to a plain error (a 500 from our API). `fetch` retries once after 200ms on a network error, a timeout or a 5xx, never on 401/403/404 or a refused token, and not when the caller's context is done; each attempt has its own `SCANNER_REGISTRY_TIMEOUT`.
- Files: `pkg/v2/registry/registry.go`, `pkg/v2/registry/errors_test.go`
- Tests run: `go test -short -race -count=3 -run TestResolve_Errors ./pkg/v2/registry/` -> ok; `go test -short -race ./pkg/v2/...` -> ok. Cases: unknown tag (not found, 2 requests: challenge + 404); wrong robot password (auth failed, 1 request, 1 token request); 403 (auth failed, 1 request); 500 twice (unavailable after exactly 2 requests); 502 then 200 (resolves); a registry that never answers with a 100ms timeout (unavailable, `DeadlineExceeded`, 2 requests, under 2s); a closed server (unavailable); 400 (plain error, 1 request); the caller's 100ms deadline (unavailable, no retry).
- Decisions / surprises: none.
- Next: P6-3

### 2026-10-15  P6-1  Part 2: Harbor registry client
- Status: done (P6-1 complete)
- What changed: new package `pkg/v2/registry`:
  - `NewClient(cfg)` uses `SCANNER_REGISTRY_URL` (scheme and host only; `http://` allowed with a WARN) and an `oci.Client` with the robot account.
  - `ValidateImage(Image)` checks the OCI distribution rules: path components `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`, tag `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`, repository/name at most 255 characters. These reject `..`, `%` and empty components; the error wraps `ErrInvalidName` (400 in P9-2).
  - `Resolve(ctx, Image)` validates first (no request for an invalid name), sends `HEAD` on `/v2/<repository>/<name>/manifests/<tag>` with Accept = OCI index, Docker manifest list, OCI manifest, Docker v2 manifest, and takes `Docker-Content-Digest`. Without it, it sends `GET` and hashes the exact bytes. It returns the digest, the media type (parameters dropped) and `Reference` = `<host>/<repository>/<name>@<digest>` for the scan runner.
  - `fetch` gives each request its own `SCANNER_REGISTRY_TIMEOUT` and reads at most 4 MiB.
  - Config `RegistryTimeout` (`SCANNER_REGISTRY_TIMEOUT`, 15s). `store.Image` has `media_type`.
- Files: `pkg/v2/registry/registry.go`, `pkg/v2/registry/registry_test.go`, `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`, `pkg/v2/store/models.go`, `pkg/v2/store/models_test.go`
- Tests run: `go test -short -race -count=2 ./pkg/v2/registry/` -> ok, 86.0%; `make test` -> ok; integration `./test/integration/store/` -> ok. Fake Harbor: tokens only for the robot's basic credentials; a plain manifest (digest, media type without charset, reference by digest); an image index; no `Docker-Content-Digest` (GET + sha256 of the exact bytes); one token for all resolves. Validation table: 4 valid, 16 invalid (uppercase, `..`, `%2e`, empty components, leading separators, bad tags, too long). An invalid name sends no request. Bad registry URLs.
- Decisions / surprises: error mapping and retry are P6-2; until then a non-200 status is a plain error.
- Next: P6-2

### 2026-10-15  P6-1  Part 1: shared OCI client (`pkg/v2/oci`)
- Status: partial (P6-1 continues with the registry client)
- What changed:
  - New package `pkg/v2/oci`, `Client`:
    - `NewClient(httpClient, creds)` (sets `DropAuthOnRedirect` when the HTTP client has no redirect rule).
    - `Do(ctx, method, url, accept)` sends the request and answers up to `MaxChallenges` (3) 401 challenges, then returns the registry's 401. Bearer: a token from the challenge realm; a token the registry refuses after it was sent is dropped and fetched again. Basic: the credentials, when there are any.
    - Tokens are cached per realm|service|scope until `expires_in` (default 60s) minus 5s; one fetch per key at a time, other callers wait (single-flight).
    - The credentials go to the token endpoint as basic auth. A plain-`http` realm is accepted only when the request itself is plain `http`. A 401/403 from the token endpoint is `ErrTokenDenied`. Errors name the realm host only.
  - `dbmgr` now uses it with anonymous credentials (`registryClient{oci, ref}`, pre-check manifest stage); its own `get`, `send`, `getToken` and `dropAuthOnRedirect` were removed, and their tests moved to `pkg/v2/oci`.
- Files: `pkg/v2/oci/client.go`, `pkg/v2/oci/client_test.go`, `pkg/v2/dbmgr/registry.go`, `pkg/v2/dbmgr/precheck.go`, `pkg/v2/dbmgr/registry_test.go`, `pkg/v2/dbmgr/precheck_stages_test.go`
- Tests run: `go test -short -race -count=3 ./pkg/v2/oci/` -> ok, 91.2%; `go test -short -race -count=3 ./pkg/v2/dbmgr/` -> ok, unchanged behaviour (token reused for the blob, no token on the CDN redirect, pre-check token flow); `make test` -> ok. New oci cases: anonymous token cached for 3 requests with the right scope; basic credentials reach the token endpoint; refused credentials give `ErrTokenDenied` without the user or password; a token expires at `expires_in` minus 5s and is fetched again; a revoked token is replaced; 10 concurrent requests share one token fetch; a registry that refuses every token gets exactly `MaxChallenges+1` requests and the 401 back; plain-http realm allowed for a plain-http registry and refused for an https one; invalid realms; Basic challenge with and without credentials; the redirect rule; a caller's own redirect rule is kept.
- Decisions / surprises: requests no longer send a token up front; each request is answered by a 401 first and then reuses the cached token (one extra round trip, no extra token fetch). It keeps the client simple: the cache key comes from the challenge.
- Next: P6-1 part 2 (registry client)

### 2026-10-15  P5-6  Follow-up: first ready after boot
- Status: done
- What changed: `NewDBStateStore(client, instanceID, cacheDir)` registers `onReady` instead of `Flush`. The first time MongoDB is ready after boot: if no `Save` happened yet (no update run completed), `Load` the stored state first (with the disk-digest check); a failed load is retried on the next ready transition unless a run saves first. If a run already saved, the memory state is written. Then `Flush`. `Load(ctx)` now uses the store's cache directory; the startup wiring (P9-1) no longer needs a separate `Load` call.
- Files: `pkg/v2/store/dbstate.go`, `pkg/v2/store/dbstate_test.go`, `test/integration/store/dbstate_test.go`
- Tests run: `go test -short -race -count=2 ./pkg/v2/...` -> ok; `make test` -> ok; `go test -tags=integration ./test/integration/...` -> ok. New integration cases, both booting with MongoDB unreachable over a stored confirmed state: without a run, MongoDB comes back and the stored state (confirmation kept, digest matches the disk) appears in memory while the stored document stays as it was; with a run saved first, the memory state replaces the stored document and stays in memory.
- Decisions / surprises: none.
- Next: P6-1

### 2026-10-15  P5-6  Follow-up: db_state retention, instance id warning
- Status: done
- What changed:
  - Config: `DBStateRetention` (`SCANNER_DB_STATE_RETENTION`, default `7d`); startup error when it is invalid or shorter than twice `SCANNER_DB_CHECK_INTERVAL`. When `SCANNER_INSTANCE_ID` falls back to the hostname, `GetConfig` logs a WARN asking to set it (for example in compose).
  - Store: `DBStateDocument.UpdatedAt` is set on every write. `EnsureSchema` creates `db_state.updated_at_ttl` next to `db_checks.at_ttl`; both go through one `ensureTTL(index, retention)` (create, or `collMod` when the retention changed). `ensureTTL` refuses a retention under 1s, because a zero TTL would delete everything at once.
- Files: `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`, `pkg/v2/store/schema.go`, `pkg/v2/store/client.go`, `pkg/v2/store/models.go`, `pkg/v2/store/dbstate.go`, `pkg/v2/store/models_test.go`, `test/integration/store/schema_test.go`, `test/integration/store/mongo_test.go`
- Tests run: `go test -short -race ./pkg/v2/...` -> ok (config 98.9%); `make test` -> ok; `go test -tags=integration ./test/integration/...` -> ok. New: config default 7d, explicit 3d, invalid value, 36h with a 1d interval refused; WARN logged with the hostname, none when the id is set. Integration: `db_state.updated_at_ttl` is 604800 and becomes 172800 through `collMod`; a zero retention gives an error naming `db_state.updated_at_ttl`.
- Decisions / surprises: the new zero-retention guard found a test bug from P5-1: `mongoConfig` in the integration tests set no retention, so the client tests had been creating a `db_checks` TTL index of 0 seconds without failing. Both retentions are set there now. The instance-id WARN, like the fallback-interval WARN, is logged by `GetConfig` even when v2 is disabled; P9-1 handles both.
- Next: first-reconnect load

### 2026-10-15  P5-6  Follow-up: deterministic db_checks ids
- Status: done
- What changed: `DBCheck.ID` is a string, `DBCheckID(instance, db, runStartedAt, source)` = "<instance_id>:<db>:<run_started_at RFC3339Nano UTC>:<source>". `DBStateStore.Save` takes the run start from the first source's pre-check start. `MongoDBChecks.Add` writes with an unordered `BulkWrite` of `ReplaceOne` + upsert on `_id`; `MemoryDBChecks.Add` replaces by id too.
- Files: `pkg/v2/store/models.go`, `pkg/v2/store/dbstate.go`, `pkg/v2/store/repositories_mongo.go`, `pkg/v2/store/memory.go`, `pkg/v2/store/models_test.go`, `pkg/v2/store/dbstate_test.go`, `pkg/v2/store/storetest/storetest.go`, `test/integration/store/dbstate_test.go`
- Tests run: `go test -short -race -count=3 ./pkg/v2/...` -> ok; integration `./test/integration/store/` -> ok. New: contract "adding the same rows twice keeps one of each" (fake and MongoDB; the second write replaces). Unit `TestDBStateStore_FlushTwiceDoesNotDuplicateChecks`: a repository that stores the rows but reports a failure on the first `Add` (a timeout after the write); the second `Flush` sends the same ids and the rows stay 2, both carrying the run start.
- Decisions / surprises:
  - The same source listed twice in `SCANNER_DB_SOURCES` gives both rows of a run the same id, so only the later one is kept. This is harmless: duplicate sources are a config mistake, and the state keeps all results.
  - The integration test that saved 10 runs in a tight loop now gives each run its own start time; with real timestamps, runs within the same millisecond would have shared ids.
- Next: instance id WARN and `db_state` retention

### 2026-10-15  P5-7  MongoDB integration tests
- Status: done
- What changed: the MongoDB integration tests were written with each task (P5-1 to P5-6) in `test/integration/store/` (`mongo_test.go`, `schema_test.go`, `repositories_test.go`, `dbstate_test.go`, one `mongo:7` container per test function). Added for P5-7: an end-to-end test where a real `dbmgr.Updater` run (one source with a closed port) goes through `DBStateStore` into `db_state` (degraded, `tcp_refused`) and `db_checks` (instance id, class, per-stage results); and the older-schema-version path (stored 0 is migrated and set to 1).
- Files: `test/integration/store/dbstate_test.go`, `test/integration/store/schema_test.go`
- Tests run: `make test-integration` -> ok (Harbor adapter API, Redis store, MongoDB store); `go test -count=2 -tags=integration ./test/integration/...` -> ok (earlier, P5-6); `make test` -> ok. Coverage of `pkg/v2/store`: integration tests alone 71.6%, unit tests alone 52.6%, merged 93.2%. The remaining gaps are error branches (a failed GridFS delete after a failed save, a missing `db_checks` collection when listing its indexes, the hostname error).
- Decisions / surprises: `make test-integration` needs Docker and pulls `mongo:7` on first use (about 60s); CI (`build.yml`) already runs it.
- Next: P6-1

### 2026-10-15  P5-6  DB state in MongoDB, per instance
- Status: done
- What changed:
  - `pkg/v2/store/dbstate.go`: `DBStateStore` implements `dbmgr.StateStore`. `Get` reads memory only. `Save` updates memory, marks the DB unwritten, buffers one `db_checks` row per source of the run (instance id, db, `at` = the pre-check start), and flushes if `Client.Ready()`; it never fails. `Flush` (one at a time) takes the unwritten states and buffered checks out under the lock and writes them without it: `db_state` with `ReplaceOne` + upsert on `_id` "<instance_id>:<db>", checks through `MongoDBChecks.Add`. What fails is put back (states re-marked; checks back before newer ones, bounded). It logs WARN with the dropped count. The buffer holds `MaxBufferedDBChecks` = 1000 and drops the oldest. `Load(ctx, cacheDir)` reads this instance's documents at startup and, when a stored digest differs from `dbmgr.InstalledDigest` on disk, uses the disk digest and clears `last_confirmed_current_at` and `newer_available`; states already in memory are kept.
  - `Client.OnReady(f)`: functions run in `Monitor` each time MongoDB becomes ready (after the schema step); `NewDBStateStore` registers its `Flush` there, so the latest state is written after a reconnect without a new run.
  - Models: `DBStateDocument` has `instance_id` and `db`; `DBCheck` has `instance_id`.
  - Config `InstanceID` (`SCANNER_INSTANCE_ID`, default `os.Hostname()`; error if both are missing).
  - `dbmgr.installedDigest` exported as `InstalledDigest` for the startup check.
- Files: `pkg/v2/store/dbstate.go`, `pkg/v2/store/dbstate_test.go`, `pkg/v2/store/client.go`, `pkg/v2/store/models.go`, `pkg/v2/store/models_test.go`, `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`, `pkg/v2/dbmgr/*` (rename), `test/integration/store/dbstate_test.go`
- Tests run: `go test -short -race -count=3 ./pkg/v2/...` -> ok; `make test` -> ok; `go test -count=2 -tags=integration ./test/integration/...` -> ok (config coverage 98.7%: the "hostname unknown" branch cannot be triggered in a test).
  - Unit, MongoDB unreachable: `Save` returns in under 100ms and `Get` sees it; the buffer of 3 keeps the newest 3 and counts 1 dropped; a failed `Flush` logs the dropped count and both write errors, keeps the state unwritten and the checks in order, and a later run's checks go after them; a real `dbmgr.Updater` completes three runs in under a second each and its degraded state is kept in memory.
  - Integration (`mongo:7`):
    - two instances save 10 runs each concurrently into one database: each has its own document with its own last digest and 10 `db_checks` rows;
    - with MongoDB down (forwarder off) a saved state is not written; after the forwarder starts, the document and its check appear with no further `Save`;
    - `Load` with a stored digest different from the disk clears the confirmation and uses the disk digest, a matching digest keeps it, and another instance's document is not loaded.
- Decisions / surprises:
  - `db_checks` rows come from `state.LastSources` at `Save`, because each `Save` from the updater is one run; this needed no change to the `StateStore` interface (documented on `DBStateStore`).
  - If MongoDB is down at startup, `Load` fails and the instance starts from memory; its next flush then replaces the stored document. Wiring (startup order, `Load` with a timeout) comes in P9-1.
- Next: P5-7

### 2026-10-15  P5-5  Follow-up: GridFS upload order and cleanup
- Status: done
- What changed: in `pkg/v2/store/reports.go`:
  - `ReportStore.Attach` first deletes earlier GridFS files of the same `scan_id` (found by `metadata.scan_id`), then uploads with metadata `scan_id` and `uploaded_at`.
  - New `ReportStore.Discard` deletes a scan's file.
  - New `SaveWithReport(ctx, reports, scan, report, save)` holds the order: attach (upload first), save the scan document, and on a failed save discard the file at once (best effort, WARN if that fails too) and return the save error.
  - The memory fake does the same.
- Files: `pkg/v2/store/reports.go`, `pkg/v2/store/storetest/storetest.go`, `test/integration/store/repositories_test.go`
- Tests run: `go test -short -race -count=2 ./pkg/v2/...` -> ok; `make test` -> ok; integration against `mongo:7` -> ok. New contract cases, run on the fake and on MongoDB: a retry of the same scan deletes the earlier file; a failed save deletes the file uploaded for it and returns the save error; a successful save keeps the file; a small report has no file. MongoDB only: after three attempts for one scan there is one file in `reports.files`, with `metadata.scan_id` and a recent `metadata.uploaded_at`.
- Decisions / surprises: none.
- Next: P5-6

### 2026-10-15  P5-5  Large reports in GridFS
- Status: done
- What changed: `pkg/v2/store/reports.go`:
  - `ReportStore` interface: `Attach(ctx, *Scan, report)` keeps the report in `scan.Report` up to the limit, otherwise uploads its BSON to the GridFS bucket `reports` (file name = scan id) and sets `scan.ReportGridFSID`; `Load(ctx, scan)` reads it back from either place (nil when there is none).
  - `MongoReports` (GridFS, with the operation deadline) and `MemoryReports` (fake). Constant `ReportInlineLimit` = 8 MiB of BSON.
  - Contract tests `storetest.ReportStore`, run against both.
- Files: `pkg/v2/store/reports.go`, `pkg/v2/store/storetest/storetest.go`, `pkg/v2/store/memory_test.go`, `test/integration/store/repositories_test.go`
- Tests run: `go test -short -race -count=3 ./pkg/v2/...` -> ok; `make test` -> ok; `go test -tags=integration ./test/integration/...` -> ok. Contract: small stays inline, large goes to GridFS and loads back equal, no report gives nil, an unknown GridFS id is an error. MongoDB only: a report of about 20 MB is refused inline by MongoDB, then stored through GridFS with the default limit; the scan document is saved, read back, and the report loads back identical.
- Decisions / surprises:
  - The threshold is a code constant (8 MiB, half of the 16 MiB document limit), not a setting; DEMAND only says "above a size threshold". To confirm with the owner.
  - GridFS files are not deleted with their scans: retention is deferred (DEMAND section 14). A file uploaded for a scan whose document then fails to save stays orphaned until retention exists.
- Next: P5-6

### 2026-10-15  P5-4  Repositories, fakes and contract tests
- Status: done
- What changed:
  - `pkg/v2/store/repository.go`: interfaces and the sentinel errors `ErrNotFound` and `ErrDuplicateRequestID`.
    - `ScanRepository`: `Create`, `Get`, `GetByRequestID`, `LastDone(digest)` (newest finished `done` scan, for the cache).
    - `PlatformRepository`: `Seen(types, digest, at)`, an upsert with `$setOnInsert` for first_seen_at and example_digest, `$set` last_seen_at and `$inc` seen_count, repeated once on a duplicate key from a concurrent insert; plus `List`.
    - `DBCheckRepository`: `Add`, `Recent(db, limit)`, newest first.
  - `repositories_mongo.go`: the MongoDB implementations; every call uses the operation deadline. A duplicate key is `ErrDuplicateRequestID` only when it comes from `request_id_unique`.
  - `memory.go`: in-memory fakes with the same behaviour, for the unit tests of later phases.
  - `storetest/storetest.go`: contract tests run against both (memory in `memory_test.go`, MongoDB in `test/integration/store/repositories_test.go`).
- Files: `pkg/v2/store/repository.go`, `pkg/v2/store/repositories_mongo.go`, `pkg/v2/store/memory.go`, `pkg/v2/store/memory_test.go`, `pkg/v2/store/storetest/storetest.go`, `test/integration/store/repositories_test.go`
- Tests run: `go test -short -race -count=3 ./pkg/v2/...` -> ok; `make test` -> ok; integration against `mongo:7` -> ok. Contract cases: create and get (also by request id), not found for all three reads, unique `request_id` with scans without one not colliding, the same scan id twice is an error but not `ErrDuplicateRequestID`, `LastDone` ignores failed, queued and other digests; platform first sighting creates and later sightings count with first_seen and example digest kept; empty list; DB checks per DB, newest first, limited, durations kept. MongoDB only: 10 concurrent first sightings of one platform give `seen_count` 10 and no errors.
- Decisions / surprises: only the operations needed so far; queue claim and lease come in P8, list and filter queries in P9-5, the DB state store in P5-6.
- Next: P5-5

### 2026-10-15  P5-3  Schema setup and indexes
- Status: done
- What changed:
  - `pkg/v2/store/schema.go`: `Client.EnsureSchema(ctx)`:
    1. Upserts `schema_version` (`_id` "schema") with `$setOnInsert`; a duplicate-key error from a concurrent insert counts as "exists".
    2. Reads the version and refuses a newer stored version.
    3. Runs migrations if older (none yet).
    4. Creates each index with its own `createIndexes` call: `request_id_unique` (unique, partial on `{request_id: {$type: "string"}}`), `image_digest_state_finished_at`, `customer_ids_finished_at`, `state_queued_at`.
    5. Creates the `at_ttl` TTL index on `db_checks.at` or, if it exists with another `expireAfterSeconds`, updates it with `collMod`.
    6. Sets the version when it was older.
    - An index conflict (codes 85 and 86) gives an error naming `<collection>.<index>`; nothing is ever dropped.
  - `client.go`: `Monitor` runs `EnsureSchema` while Mongo is up and the schema is not ready, so at startup, after every up transition, and on every ping until it succeeds. "Schema ready" is reset when Mongo goes down. `Ready()` = up and schema ready. A schema ERROR is logged only when its message changes.
  - `Scan.RequestID` is now `omitempty`.
  - New config `DBChecksRetention` (`SCANNER_DB_CHECKS_RETENTION`, default `30d`, at least 1s, otherwise a startup error).
- Files: `pkg/v2/store/schema.go`, `pkg/v2/store/client.go`, `pkg/v2/store/models.go`, `pkg/v2/store/client_test.go`, `pkg/v2/store/models_test.go`, `test/integration/store/schema_test.go`, `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race -count=3 ./pkg/v2/...` -> ok; `make test` -> ok; `go test -tags=integration ./test/integration/...` -> ok.
  - Unit: up but schema failing is not ready, retried each check and logged once; success makes it ready and it is not re-run while up; going down and up runs it again; schema errors do not log the URI; a scan without request id has no `request_id` field.
  - Integration (`mongo:7`):
    - two clients run `EnsureSchema` at the same time on a fresh DB, 5 rounds, no errors;
    - a second run leaves the indexes and the `schema_version` document identical;
    - two scans without `request_id` insert, a duplicate `request_id` is rejected, and the partial filter is as specified;
    - TTL `expireAfterSeconds` is 2592000 and becomes 604800 through `collMod` when the retention changes;
    - a pre-existing `state_queued_at` index with other keys gives the error naming it, the replica stays not ready, and the index is untouched;
    - a stored version 99 gives the "newer" error, not ready, and the version is untouched;
    - Mongo down at startup (forwarder off): not ready, then ready with indexes after the forwarder starts.
- Decisions / surprises: `Scan.RequestID` had to become `omitempty` (an empty string is a string and would collide on the partial unique index). The TTL `expireAfterSeconds` is an int32 in MongoDB (about 68 years maximum), far above any sensible retention.
- Next: P5-4

### 2026-10-15  P5-2  MongoDB models and collections
- Status: done
- What changed: `pkg/v2/store/models.go`:
  - Collection names `scans`, `platforms`, `db_state`, `db_checks`; scan states `queued`, `scanning`, `done`, `failed`.
  - `Scan` (the job record, DEMAND section 10) with `Image`, `ScanOptions`, `TrivyInfo`. Times not known yet (`started_at`, `finished_at`, `lease_until`) are pointers with `omitempty`, so they are absent rather than year 0001; this keeps the indexes and the "not finished" queries simple. `Report` is an open `bson.M` until the scan runner (P7) fixes its shape.
  - `Platform`.
  - `DBStateDocument` (`_id` "db" or "java-db" plus an inline `dbmgr.DBState`).
  - `DBCheck` (db, at, plus an inline `dbmgr.SourceResult`).
  - `bson` tags added to `dbmgr.DBState`, `SourceResult`, `CheckResult`, `StageResult` (same snake_case names as their JSON) and `Metadata` (snake_case; its JSON names stay Trivy's file format). One struct per concept, no copies; `dbmgr` does not import `store`.
- Files: `pkg/v2/store/models.go`, `pkg/v2/store/models_test.go`, `pkg/v2/dbmgr/state.go`, `pkg/v2/dbmgr/precheck.go`, `pkg/v2/dbmgr/update.go`, `pkg/v2/dbmgr/metadata.go`, `test/integration/store/mongo_test.go`
- Tests run: `go test -short -race -count=3 ./pkg/v2/...` -> ok; `make test` -> ok. Integration: `Scan` and `DBStateDocument` round-trip through `mongo:7` unchanged. Unit cases: field names of every document and sub-document match DEMAND section 10; a queued scan leaves out unknown times, report and worker; in-memory BSON round trips are equal.
- Decisions / surprises: durations in stored pre-check results are int64 nanoseconds (BSON's default for `time.Duration`).
- Next: P5-3

### 2026-10-15  P5-1  MongoDB client
- Status: done
- What changed: new package `pkg/v2/store`, `client.go`:
  - `NewClient(cfg)` creates the driver client with `SCANNER_MONGO_CONNECT_TIMEOUT` and `SCANNER_MONGO_SERVER_SELECTION_TIMEOUT`. It does no network I/O, so an unreachable Mongo is not a startup error; only a bad URI is.
  - `OperationContext(ctx)` adds the `SCANNER_MONGO_OPERATION_TIMEOUT` deadline; every Mongo call must use it.
  - `Monitor(ctx, interval)` pings at once and then every interval (`store.PingInterval` = 5s in production), sets the `Up()` flag, and logs only changes (plus the first failure). Readiness and the future `mongo_up` gauge read `Up()` and never call Mongo.
  - `Disconnect`.
  - `redactURI(err, uri)` removes the URI, its user info, the password and the decoded password from a message, and returns a new error that does not wrap the original. It is used for client-creation errors and logged ping errors.
  - New config: `MongoConnectTimeout` (5s), `MongoServerSelectionTimeout` (5s), `MongoOperationTimeout` (10s).
  - New dependency `go.mongodb.org/mongo-driver/v2 v2.9.1` (v2.9.2 was only 9 days old).
- Files: `pkg/v2/store/client.go`, `pkg/v2/store/client_test.go`, `test/integration/store/mongo_test.go`, `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`, `go.mod`, `go.sum`
- Tests run:
  - `go test -short -race -count=3 ./pkg/v2/...` -> ok; `make test` -> ok.
  - `go test -tags=integration ./test/integration/...` -> ok (Harbor adapter, Redis and the new Mongo tests).
  - Unit, with a fake ping: unreachable is not an error and does no I/O; ping has a deadline; first failure logged once, repeated failures not logged, recovery and going down logged; Monitor pings and stops on cancel; operation deadline.
  - Redaction: malformed URIs through the driver; a crafted error that quotes the full URI, the user info and the decoded password; a ping failure against a URI with credentials.
  - Integration with `mongo:7`, connected through a local TCP forwarder the test switches off and on: reachable (up, insert and find with a deadline); unreachable at startup (not up after 3s, no error, no exit); the forwarder starts (up); it stops and closes its connections (not up); it starts again (up).
- Decisions / surprises:
  - The driver v2.9.1 does not quote the URI in any of its parse errors that were tried (checked by printing the raw errors), so the crafted-error test is what really checks the redaction; the driver cases guard future versions.
  - Reconnecting is done by the driver: the client is created once and never recreated, and recovery took a few seconds in the integration test. No extra backoff loop was added (see the ninth-round Decisions).
  - Wiring (`main.go`, readiness probe, 503) comes in P9-1 and P10-2.
- Next: P5-2

### 2026-10-15  P4-5  Fake-clock tests
- Status: done
- What changed: `Updater.after` (default `time.After`) is the wait used by `Run`, next to `Updater.now`. `clock_test.go` has a `fakeClock` whose `After` records each requested wait and ends it only when the test fires it.
- Files: `pkg/v2/dbmgr/updater.go`, `pkg/v2/dbmgr/clock_test.go`
- Tests run: `go test -short -race -count=5 ./pkg/v2/...` -> ok; coverage config 100%, dbmgr 89.5%; `make test` -> ok; `go test -tags=integration ./test/integration/...` -> ok. Cases, without real waiting:
  - `GetConfig` with `SCANNER_DB_CHECK_INTERVAL` unset gives 3h; a real `Run` then asks for 15m after a degraded first run (newer DB not installed), 3h after the retry installs, and 3h again when up to date.
  - `1d` gives a 24h wait.
  - The on-demand min gap follows the clock: 59s after a run there is no refresh, 61s after there is one.
  - Freshness is `ok` exactly at max age and `stale` one second later.
- Decisions / surprises: the age WARN in `update` still uses the real clock; it only logs, so it was not worth another injection point.
- Next: P5-1

### 2026-10-15  P4-4  On-demand refresh
- Status: done
- What changed: `Updater.RefreshForScan(ctx, maxAge)` returns the Trivy DB state and its freshness for the request:
  - fresh for `maxAge`, or mode `degraded`: returns at once, no run;
  - a run finished within `SCANNER_ONDEMAND_REFRESH_MIN_GAP`: returns the current state, no new run;
  - otherwise `UpdateNow` with a `SCANNER_ONDEMAND_REFRESH_WAIT` wait limit, then rereads the state; on timeout it logs a WARN and returns the old state (`stale`) while the run goes on.
  - `Updater` now records `lastFinished` per run and has a `now` clock field (`time.Now`, replaceable by tests). New config `OnDemandRefreshWait` and `OnDemandRefreshMinGap` (60s each).
- Files: `pkg/v2/dbmgr/updater.go`, `pkg/v2/dbmgr/refresh_test.go`, `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race -count=5 -run TestUpdater_RefreshForScan` -> ok; `go test -short -race ./pkg/v2/...` -> ok; config 100%. Cases: fresh (no run), stale (run, then `ok` with a new confirmation), degraded (no run, `stale`), run within the min gap reused (no run, `stale`), slow refresh (returns `stale` in under 250ms with a 50ms wait, the install finishes in the background and the state becomes `ok`), store error returned.
- Decisions / surprises: the scan worker (P8-2) calls `RefreshForScan`; it is not called from any HTTP handler. Only the Trivy DB's state decides freshness (the `db` block of responses is about the Trivy DB); a refresh run updates both DBs.
- Next: P4-5

### 2026-10-15  P4-3  Freshness and DB age from the stored state
- Status: done
- What changed: `DBState.Freshness(maxAge, now)` uses the stored `newer_available` and `last_confirmed_current_at` through `Freshness`; `DBState.Age(now)` is `db_age` (now minus the active DB's `UpdatedAt`, zero when unknown). The API (P9) and health (P10) read a `DBState` from the store and call these.
- Files: `pkg/v2/dbmgr/state.go`, `pkg/v2/dbmgr/state_test.go`
- Tests run: `go test -short -race -run TestDBState ./pkg/v2/dbmgr/` -> ok. Cases: confirmed 2h ago is ok for 3h and stale for 1h, age 30h, `newer_available` stale even with 24h, never confirmed is stale, no metadata gives age 0.
- Decisions / surprises: none.
- Next: P4-4

### 2026-10-15  P4-2  Follow-up: injected write failures, digest read from disk
- Status: done
- What changed:
  - `downloadDB` creates extracted files through the package variable `createFile` (returns `extractedFile`: Write, Sync, Close). In tests, `fakeFullDisk(t, n)` returns a real file that fails with `ENOSPC` (a `*fs.PathError`) after n bytes, like a full disk mid-write.
  - The two read-only-directory tests are replaced by injected-failure tests: no `Chmod`, no root skip, so they work as root.
  - New `TestUpdater_InstalledDigestFromDisk`: install with one updater, then a new updater with a new empty state store over the same cache directory does not download (one blob request in total), confirms the DB current, and saves state `normal` with the right digest. The installed digest comes from the `manifest-digest` file in the version directory (`installedDigest`), never from the state store.
- Files: `pkg/v2/dbmgr/download.go`, `pkg/v2/dbmgr/download_test.go`, `pkg/v2/dbmgr/update_test.go`, `pkg/v2/dbmgr/updater_test.go`
- Tests run: `go test -short -race -count=5 ./pkg/v2/...` -> ok. `TestUpdate_InstallWriteError` asserts the same as before (`install_error` with "no space left on device", degraded, `newer_available`, old DB and digest kept, no partial directory, next run installs and clears the flag). `TestDownloadDB_LocalWriteError` checks `errors.Is` for both `errLocalDisk` and `ENOSPC`.
- Decisions / surprises: the fake does not embed `*os.File`, because `io.Copy` would use the embedded `ReadFrom` and bypass the failing `Write`.
- Next: P4-3

### 2026-10-15  P4-2  DB state store
- Status: done
- What changed: `pkg/v2/dbmgr/state.go`:
  - `DBState` (mode, active source, manifest digest, `last_upstream_check_at`, `last_confirmed_current_at`, `newer_available`, `installed_at`, metadata, last per-source results) is the future `db_state` document and the data for `GET /api/v2/db`.
  - `DBState.apply(UpdateResult)` holds the merge rules: when no source answered, the active source, the upstream check time and `newer_available` are kept; a confirmed or installed DB sets `last_confirmed_current_at`; an install sets `installed_at`.
  - `StateStore` interface (`Get`, `Save`, keyed by "db" and "java-db") with `MemoryStateStore`; MongoDB comes in P5-6.
  - `NewUpdater` now takes a store, and `runOnce` saves each DB's state after its update. A store error is logged as ERROR and does not stop the DB update (P5 decides how the Mongo hard dependency treats it).
- Files: `pkg/v2/dbmgr/state.go`, `pkg/v2/dbmgr/state_test.go`, `pkg/v2/dbmgr/updater.go`, `pkg/v2/dbmgr/updater_test.go`
- Tests run: `go test -short -race -count=10 ./pkg/v2/...` -> ok; `make test` -> ok; coverage dbmgr 89.6%. Cases: `apply` rules (no answer keeps the flag, source and times; newer sets the flag; confirmation clears it; install sets `installed_at` and the metadata); the memory store (zero state when missing, separate per DB); a three-run sequence through the updater and one store (newer not installed: degraded, flag, `stale`; no source answers: flag and upstream info kept; download works: normal, flag cleared, `ok`); no Java state without Java sources; a failing store logs ERROR and the DB is still installed.
- Decisions / surprises: none.
- Next: P4-3

### 2026-10-15  P3-6  Follow-up: disk check reverted, local write errors are install_error
- Status: done
- What changed: revert commit `9f42746` removed the free-space check, the `disk_space` class, the extract ratios, `freeSpace` and its tests; the Java DB download cap was restored in the same commit. Then `downloadDB` marks file errors while extracting (open, write, fsync, close, all `*fs.PathError`) with `errLocalDisk`, and `update` reports them as `install_error` instead of `download_error`.
- Files: `pkg/v2/dbmgr/update.go`, `pkg/v2/dbmgr/download.go`, `pkg/v2/dbmgr/update_test.go`, `pkg/v2/dbmgr/download_test.go`, `docs/direct-scan/*`
- Tests run: `go test -short -race -count=3` (write-error and download tests) -> ok; `go test -short -race ./pkg/v2/...` -> ok. `TestUpdate_InstallWriteError`: v1 installed, versions directory made read-only, v2 offered: `install_error` ("permission denied"), `degraded`, `newer_available`, old DB and digest kept, version list unchanged (no partial directory); after write access is restored, the next run installs v2 and clears the flag. `TestDownloadDB_LocalWriteError`: a read-only target directory gives an error that `errors.Is(errLocalDisk)`. Both skip as root.
- Decisions / surprises: a real full disk (ENOSPC) cannot be made in a unit test without root; the read-only directory gives the same kind of file error on the same code path.
- Next: P4-2

### 2026-10-15  P4-1  DB updater loop
- Status: done
- What changed: `pkg/v2/dbmgr/updater.go`:
  - `NewUpdater(ctx, cfg, cacheDir)`, where ctx is the service lifetime.
  - `Run()` installs the Trivy seed (and the Java seed only when Java sources exist), updates at once, then waits `SCANNER_DB_CHECK_INTERVAL`, or `SCANNER_DB_RETRY_INTERVAL` while either DB is degraded, and returns when ctx ends.
  - `UpdateNow(waitCtx)` starts a run in its own goroutine, or joins the run in progress (single-flight), and waits for it. `waitCtx` only bounds the waiting: a caller that gives up returns its context error and the run goes on with the lifetime context.
  - `UpdateResults` holds the Trivy DB result and the Java DB result (nil when `SCANNER_JAVA_DB_SOURCES` is empty), plus `Degraded()`.
  - New config `DBRetryInterval` (`SCANNER_DB_RETRY_INTERVAL`, default 15m).
- Files: `pkg/v2/dbmgr/updater.go`, `pkg/v2/dbmgr/updater_test.go`, `pkg/v2/dbmgr/update_test.go` (Java fake moved to file level), `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race -count=10 ./pkg/v2/...` -> ok; `make test` -> ok; coverage config 100%, dbmgr 88.5%. Cases: first run at startup, then runs on a 100ms check interval with no second download; the retry interval while degraded (counted connections); back to the 1h check interval after the retry installs (no more runs for 300ms); the seed is installed before the first update and the Java seed is not installed without Java sources; Run stops within 5s of cancel (checked in cleanup); two concurrent `UpdateNow` calls share one download; a caller with a 50ms wait returns `DeadlineExceeded` and the run goes on; Java only with sources; a degraded Java DB makes the results degraded.
- Decisions / surprises: the Java seed is only installed when Java sources are configured, so "no Java sources" always means "no Java DB". Tests use short real intervals; P4-5 adds a fake clock where exact timing matters. Not wired into `main.go` yet (P9-1).
- Next: P4-2

### 2026-10-15  P3-10  Disk space check and Java DB download cap
- Status: done
- What changed:
  - Config `JavaDBDownloadTimeout` (`SCANNER_JAVA_DB_DOWNLOAD_TIMEOUT`, default 45m); `update` uses it for the Java DB and `SCANNER_DB_DOWNLOAD_TIMEOUT` for the Trivy DB. The stall timeout is shared.
  - Before creating the version directory, `update` checks free space in the cache directory: layer size plus layer size times `dbKind.ExtractRatio` (13 Trivy DB, 2 Java DB), plus 10%. Too little space, or an error from the check, fails the source with class `disk_space` (the error gives MiB needed and available) and the loop continues. A newer DB that cannot be installed this way leads to `degraded` with `newer_available`, as for any other failure.
  - `freeSpace` is a package variable using `syscall.Statfs` (`Bavail * Bsize`), replaced in tests.
- Files: `pkg/v2/dbmgr/update.go`, `pkg/v2/dbmgr/update_test.go`, `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race -count=5` (disk space and Java cap tests) -> ok; `go test -short -race -count=3 ./pkg/v2/...` -> ok; `make test` -> ok. Cases: one byte too little fails both sources with `disk_space` and no blob request (counted atomically), exactly enough downloads, a failing check is `disk_space`, the real `statfs` returns a positive value; the Java DB installs with an expired Trivy DB cap and fails with an expired Java cap.
- Decisions / surprises: none beyond the recorded formula.
- Next: P4-1

### 2026-10-15  P3-9  Fake-registry test list complete
- Status: done
- What changed: `TestUpdate_DownloadFailuresFallBack` runs each broken download through the whole loop (different content, truncated, hang mid-download, HTTP 502). Each time the first source fails with `download_error`, the second source is installed, the run takes under 3s (stall 200ms), and no version directory is left behind. With the earlier tests this covers the whole P3-9 list: success (`TestUpdate`), wrong digest (`TestDownloadDB`), truncated, hang mid-download, fallback to the second source and all sources failing, plus the real ghcr.io run recorded below.
- Files: `pkg/v2/dbmgr/update_test.go`
- Tests run: `go test -short -race -count=5 -run TestUpdate_DownloadFailuresFallBack` -> ok; `go test -short -race -count=3 ./pkg/v2/...` -> ok; coverage config 100%, dbmgr 88.2%; `make test` -> ok
- Decisions / surprises: a P3-7 doc edit failed after its commit had been made (the edit script and the commit were not chained); fixed by amending that local commit. Doc edits and commits are now chained with `&&`.
- Next: P4-1

### 2026-10-15  P3-7  Java DB
- Status: done
- What changed: `javaDB` kind in `pkg/v2/dbmgr/update.go`: directory `java-db`, files `trivy-java.db` and `metadata.json`, layer media type `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip` (checked against the real `ghcr.io/aquasecurity/trivy-java-db:1` manifest). The Java DB uses the same `update`, `installDB` and `installSeed` code with its own sources and seed directory.
- Files: `pkg/v2/dbmgr/update.go`, `pkg/v2/dbmgr/update_test.go`
- Tests run: `go test -short -race -count=3 -run TestUpdate ./pkg/v2/dbmgr/` -> ok. Cases: the Java DB is installed next to the main DB through a fallback (refused, then ok), each keeps its own digest; the main DB layer is rejected as a Java DB; the Java seed goes into `java-db` only.
- Decisions / surprises:
  - The real Java DB layer is 983,567,002 bytes (938 MiB) compressed, and `trivy-java.db` is 1.55 GB extracted (seen in the tar listing; the full DB was not downloaded). At the default 15m `SCANNER_DB_DOWNLOAD_TIMEOUT` this needs at least about 1.1 MB/s; slower links must raise the cap. To raise with the owner.
  - `update` with no sources reports `degraded`, so the updater (P4-1) must skip the Java DB when `SCANNER_JAVA_DB_SOURCES` is empty; added to P4-1.
- Next: finish P3-9

### 2026-10-15  P3-9  Partial: real ghcr.io DB download
- Status: partial (manual real-registry part done)
- What changed: `TestManualUpdate` (build tag `manual`) runs `update` against `SCANNER_DB_SOURCES` into `SCANNER_TRIVY_CACHE_DIR`; the command is in `CLAUDE.md` section 4.
- Files: `pkg/v2/dbmgr/precheck_manual_test.go`, `CLAUDE.md`
- Tests run (2026-10-15, this dev machine, `ghcr.io/aquasecurity/trivy-db:2|direct`):
  - First run: installed. Total 43.6s: pre-check 1.6s, upstream check about 1s, download plus extract plus verify 41.0s. Manifest `sha256:01d3818690b9e3366e9b1ff67cfd480dd935803e4ecb3c65dfa07bcc3afcef47`. Layer `application/vnd.aquasec.trivy.db.layer.v1.tar+gzip`, 133,916,706 bytes (127.7 MiB) compressed. Extracted `trivy.db` 1,623,306,240 bytes (1.62 GB), `metadata.json` 143 bytes, UpdatedAt 2026-10-15T07:10:08Z, NextUpdate 2026-10-16T07:10:08Z.
  - Second run: "DB is up to date" in 2.3s, no download.
  - Real Trivy 0.71.2: `trivy fs --cache-dir <dir> --skip-db-update --offline-scan` on a `requirements.txt` with `django==2.0.0` used the symlinked DB and found 3 CRITICAL (CVE-2019-19844, CVE-2020-7471, CVE-2025-64459). Trivy did not change the `db` symlink or the versions directory.
- Decisions / surprises:
  - The "about 70 MB" estimate was low: 128 MiB compressed, 1.62 GB on disk. With the current version, the previous version and one download in progress, the DB volume needs about 5 GB for the main DB alone. P11-4 (Dockerfile and volume) must size for this, and the seed DB adds 1.6 GB to the image.
  - Version directories are created with mode 0700 (`os.MkdirTemp`); fine because Trivy runs as the same user as the scanner.
  - The manual run printed "using fallback interval", because `GetConfig` logs it even with v2 disabled (known, fixed in P9-1).
- Next: P3-7

### 2026-10-15  P3-6  Follow-up: newer DB not installed, two timestamps, newer_available
- Status: done
- What changed: in `update`, the mode is decided after the loop. No source answered: `degraded` with the "all DB sources failed" ERROR. A source offered a different digest but nothing was installed: `degraded`, `NewerAvailable` true, ONE ERROR "newer DB available but could not be installed" listing each failed source's class (replaces the WARN). Otherwise `normal`. `UpdateResult` now has `UpstreamCheckedAt` (`last_upstream_check_at`), `ConfirmedCurrentAt` (`last_confirmed_current_at`, set on an equal digest or after an install) and `NewerAvailable` (false after an install or confirmation; meaningless when no source answered, so the state must keep the stored flag). New `Freshness(newerAvailable, confirmedCurrentAt, maxAge, now)`: `stale` while newer is available or when never confirmed, otherwise compared with `maxAge`.
- Files: `pkg/v2/dbmgr/update.go`, `pkg/v2/dbmgr/update_test.go`, `pkg/v2/dbmgr/freshness.go`, `pkg/v2/dbmgr/freshness_test.go`
- Tests run: `go test -short -race -count=5 ./pkg/v2/...` -> ok; `make test` -> ok. New test: install v1 (ok), then two sources offer v2 and both downloads fail (degraded, flag set, `last_upstream_check_at` set, `last_confirmed_current_at` zero, old DB kept, exactly one ERROR naming both classes, freshness `stale` even with a recent confirmation and a 24h max age), then a later run confirms v1 from a good source (normal, flag cleared, freshness `ok`). Freshness unit tests. The existing cases also check the two timestamps.
- Decisions / surprises: the old "newer found is a WARN, not degraded" test was replaced, because the owner's decision changed the behaviour. The pure `Freshness` function is done early; P4-3 only has to wire it to the stored state.
- Next: real ghcr.io download (P3-9)

### 2026-10-15  P3-6  Source update loop
- Status: done
- What changed: `update(ctx, cfg, cacheDir, kind, sources)` in `pkg/v2/dbmgr/update.go`, per source in order: `Precheck`, then `checkUpstream` (bounded by the manifest timeout), then, if the digest differs, `downloadDB` into a new version (bounded by `SCANNER_DB_DOWNLOAD_TIMEOUT` and the stall timeout), then `readMetadata`, then `installDB`.
  - Stops on an equal digest or after an install. A failed source is recorded with its class (pre-check class, `upstream_error`, `download_error`, `install_error`) and the loop continues; failed downloads are removed.
  - Returns `UpdateResult`: mode, active source, active manifest digest, installed flag, `UpstreamCheckedAt` (set when a source answered), metadata of the active DB, and per-source `SourceResult`s with the pre-check result.
  - No source answered: mode `degraded`, one ERROR "all DB sources failed, scanning with existing DB" with each source's class, old DB kept.
  - After each run: WARN "DB is older than SCANNER_DB_AGE_WARN" with `db_age`, `updated_at` and the active source.
  - Logs "DB source selected", "DB is up to date" and "DB installed" (DEMAND 12 "DB source selection").
  - `dbKind` describes a DB (directory name, files, layer media type); `trivyDB` is the first one.
  - New config `DBAgeWarn` (`SCANNER_DB_AGE_WARN`, default `7d`; invalid or zero is a startup error).
- Files: `pkg/v2/dbmgr/update.go`, `pkg/v2/dbmgr/update_test.go`, `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`; test helpers in `registry_test.go` (fake serves `/v2/`, CA pool shared by several fakes, media type taken from `trivyDB`)
- Tests run: `go test -short -race -count=10 ./pkg/v2/...` -> ok; `make test` -> ok; coverage config 100%, dbmgr 87.9%; `go.mod` unchanged. Cases: install then up to date (the loop stops, second source not tried), pre-check fallback, download fallback (no leftover version), older mirror installed (no downgrade guard), all failed (degraded, exactly one ERROR, old DB kept, no `UpstreamCheckedAt`), a DB without UpdatedAt or with the wrong layer type is not installed, age WARN on a 10-day-old DB and none on a fresh one, no secrets in logs through SOCKS5 with a token.
- Decisions / surprises:
  - Edge case not covered by the owner's rule: a source answers with a different digest, but every download fails. The mode stays `normal` and `UpstreamCheckedAt` is set, because a source answered. A WARN "a newer DB was found but could not be installed" makes it visible. Freshness will say `ok` in that case; to raise with the owner.
  - The metadata of a downloaded DB is checked before install, because the scan cache depends on `UpdatedAt`.
  - Not yet run against the real ghcr.io DB (about 70 MB compressed); planned for P3-9 or P11-1 with the manual test.
- Next: P3-7

### 2026-10-15  P3-8  metadata.json
- Status: done (done before P3-6, because the age WARN needs it)
- What changed: `Metadata` (Version, NextUpdate, UpdatedAt, DownloadedAt) and `readMetadata(dir)` in `pkg/v2/dbmgr/metadata.go`. `UpdatedAt` is required, because the scan cache and the DB age depend on it.
- Files: `pkg/v2/dbmgr/metadata.go`, `pkg/v2/dbmgr/metadata_test.go`
- Tests run: `go test -short -race -run TestReadMetadata ./pkg/v2/dbmgr/` -> ok. The fixture is the real `metadata.json` from this machine's Trivy cache. Missing file, bad JSON and no UpdatedAt are errors.
- Decisions / surprises: `readMetadata` takes a directory, so P3-6 can check a downloaded version before installing it. `DownloadedAt` in the file is what upstream wrote; our own install time will be stored in the DB state.
- Next: P3-6

### 2026-10-15  P3-5  Seed DB
- Status: done
- What changed: config `DBSeedDir` / `JavaDBSeedDir` (`SCANNER_DB_SEED_DIR`, `SCANNER_JAVA_DB_SEED_DIR`). `installSeed(cacheDir, dbName, seedDir, files)` copies the seed files (fsynced) into a new version and installs it with an empty digest, only when no DB is active and the seed directory exists. `dbPresent(cacheDir, dbName, dbFile)` is the readiness check: the active DB file is a regular file.
- Files: `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`, `pkg/v2/dbmgr/install.go`, `pkg/v2/dbmgr/install_test.go`, `docs/direct-scan/DEMAND.md`
- Tests run: `go test -short -race ./pkg/v2/...` -> ok (config 100%); `make test` -> ok. Cases: seed installed when no DB (empty digest), installed DB kept, missing seed directory (not ready), incomplete seed is an error that leaves no version behind, a directory named `trivy.db` is not a DB.
- Decisions / surprises: wiring (calling `installSeed` at startup, readiness in the probe) comes with the updater (P4-1) and P10-2.
- Next: P3-6

### 2026-10-15  P3-4  Atomic DB swap
- Status: done
- What changed: `pkg/v2/dbmgr/install.go`: `newVersionDir(cacheDir, dbName)` creates the download target under `<dbName>-versions/`; `installDB(cacheDir, dbName, versionDir, manifestDigest)` writes `manifest-digest`, swaps the symlink with rename, and removes versions other than the new and previous ones; `installedDigest(cacheDir, dbName)` reads the active digest ("" when missing). `downloadDB` now fsyncs each extracted file before closing it, so a crash right after the swap cannot activate unflushed files.
- Files: `pkg/v2/dbmgr/install.go`, `pkg/v2/dbmgr/install_test.go`, `pkg/v2/dbmgr/download.go`
- Tests run: `go test -short -race -count=3` (install and download tests) -> ok; `go test -short -race ./pkg/v2/...` -> ok. Cases: first install (relative symlink, digest), two and three updates (only current and previous kept, failed-download leftover removed, no `db.new` left), a file opened before two swaps still reads the old content, an old-layout real `db` directory becomes the previous version, `java-db` kept separate.
- Decisions / surprises: mechanism recorded under Decisions.
- Next: P3-5

### 2026-10-15  P3-3  DB layer download
- Status: done
- What changed: `downloadDB(ctx, client, layer, destDir, stallTimeout, wantFiles)` streams the blob into a sha256 hasher (`io.TeeReader`), then gzip, then tar. It extracts only regular files whose exact top-level name is in `wantFiles` (`O_EXCL`, so nothing is overwritten and paths like `../x` are never written), then checks the size, the digest and that every wanted file was present.
  - Stall timeout: a `time.AfterFunc` that cancels the download context with the cause "download stalled: no data for X". It is reset on every read that returns data (`stallReader`).
  - Overall cap: the caller's context deadline (`SCANNER_DB_DOWNLOAD_TIMEOUT`).
  - `downloadError` adds the cause (stall or overall limit) to the read error.
- Files: `pkg/v2/dbmgr/download.go`, `pkg/v2/dbmgr/download_test.go`
- Tests run: `go test -short -race -count=10 ./pkg/v2/dbmgr/` -> ok; coverage 87%+. Cases: success through token and CDN redirect with only the wanted files extracted (README and `../evil` skipped), wrong digest, truncated layer, layer larger than the manifest, missing `metadata.json`, a server that hangs mid-download (stall 100ms), and a server sending one byte every 10ms (stall never fires, overall limit 150ms does).
- Decisions / surprises: the digest is checked after extraction into the temp dir, which is fine because nothing is installed until P3-4 swaps it in. Part of the P3-9 test list (wrong digest, truncated, hang mid-download) is done here.
- Next: P3-4

### 2026-10-15  P3-2  Upstream check
- Status: done
- What changed: `checkUpstream(ctx, client, installedDigest)` in `pkg/v2/dbmgr/download.go` gets the remote manifest and reports whether its digest differs from the installed one. An empty installed digest (seed DB, first start) counts as changed. It returns the manifest so the download needs no second request.
- Files: `pkg/v2/dbmgr/download.go`, `pkg/v2/dbmgr/download_test.go`
- Tests run: `go test -short -race -run TestCheckUpstream ./pkg/v2/dbmgr/` -> ok (same, different and empty digest, registry 404); `go vet` -> ok
- Decisions / surprises: the installed digest is passed in by the caller; it will come from the DB state (P4-2, Mongo `db_state` in P5-6). Phase 3 plan: P3-3 `downloadDB` (stall timeout, digest and size check, tar.gz extraction), P3-4 versioned directories plus a symlink swapped with `rename`, P3-6 the source loop calling Precheck, then checkUpstream, then download and install.
- Next: P3-3

### 2026-10-15  P3-1  OCI registry client
- Status: done
- What changed: `registryClient` in `pkg/v2/dbmgr/registry.go` (replaces the `getManifest` function) holds the HTTP client, the parsed repository and the anonymous pull token, so the manifest and blob requests share one token. `newRegistryClient(source)` builds a transport whose every connection, including redirects, uses `dialTLS` over the source's route.
  - `getManifest(ctx)` returns the parsed OCI manifest (layers: media type, digest, size) and its digest, computed as the sha256 of the bytes and checked against `Docker-Content-Digest`.
  - `getBlob(ctx, digest)` returns the blob body and follows CDN redirects.
  - `dropAuthOnRedirect` removes the token when a redirect changes host:port. The pre-check client uses the same rule.
- Files: `pkg/v2/dbmgr/registry.go`, `pkg/v2/dbmgr/registry_test.go`, `pkg/v2/dbmgr/precheck.go`
- Tests run: `go test -short -race -count=5 ./pkg/v2/dbmgr/` -> ok; `make test` -> ok; coverage `pkg/v2/dbmgr` 88.3%; `go.mod` unchanged. Fake OCI registry plus a separate CDN server: manifest parse and digest, digest header mismatch, manifest without layers, unknown tag, token fetched once and reused for the blob, blob redirect to the CDN without the token, redirect going through the same SOCKS5 proxy, unknown blob, redirect rule unit test.
- Decisions / surprises: the CDN test found a real token leak. net/http keeps `Authorization` on a redirect when only the port changes (it compares host names), so a mirror redirecting to another port on the same host would have received the token. Fixed with `dropAuthOnRedirect`. Raw HTTP vs library decision recorded under Decisions.
- Next: P3-2

### 2026-10-15  P2-8  Pre-check failure classes
- Status: done
- What changed: `StageResult.Class` and `CheckResult.FailureClass`; `classifyFailure(stage, err, timedOut)` maps errors with `errors.Is` / `errors.As`. connect: `ECONNREFUSED` gives tcp_refused. tls: `tls.CertificateVerificationError` gives tls_cert_invalid, an `OpError` with Op "remote error" gives tls_alert, and `ECONNRESET` / EOF give tls_reset. HTTP: the sentinel `errHTTP2NotNegotiated` gives http2_not_negotiated. On a cert error the TLS stage detail gets the peer certificate subject, issuer and expiry. The class appears in each stage log line and as `failure_class` in the "pre-check failed" line. DEMAND 7.3 item 7 lists the classes.
- Files: `pkg/v2/dbmgr/precheck.go`, `pkg/v2/dbmgr/precheck_class_test.go`, `docs/direct-scan/DEMAND.md`
- Tests run: `go test -short -race -count=10 ./pkg/v2/dbmgr/` three times -> ok (30 runs); `make test` -> ok; `go vet` -> ok. New tests: raw servers that reset (linger 0, real "connection reset by peer"), go silent, or send a fatal handshake_failure alert after reading the ClientHello; unknown-CA certificate (subject, issuer, expiry checked); refused port; blackholed SOCKS5 proxy; unknown `.invalid` host; HTTP/1.1 only; manifest 404 and hang; no class on success; class in the log.
- Decisions / surprises:
  - Extra classes beyond the owner's list, so every failure has one: `tcp_error`, `tls_error`, `http_timeout`, `http_error`, `manifest_timeout`, `manifest_error`, `config_error`. `tls_reset` also covers a plain close (EOF) during the handshake, which an interfering path can send instead of a RST.
  - Race found by the stress run: the dialers copy the context deadline onto the socket, so a connect could time out before `stageCtx.Err()` was set, and it was classified `tcp_error` in 3 of 10 runs. `runStage` now also counts `os.ErrDeadlineExceeded` as a timeout, and decides "overall vs stage" from the overall deadline itself.
- Next: P3-1

### 2026-10-15  P2-7  Manual pre-check entrypoint
- Status: done
- What changed: `pkg/v2/dbmgr/precheck_manual_test.go` (build tag `manual`) runs `Precheck` on every source in `SCANNER_DB_SOURCES`, with the normal v2 config and timeouts, printing the logs and the JSON result. It is skipped when no sources are set. The command is listed in `CLAUDE.md` section 4.
- Files: `pkg/v2/dbmgr/precheck_manual_test.go`, `CLAUDE.md`
- Tests run: `go vet -tags=manual` -> ok; run without sources -> skipped; manual run on this dev machine against `ghcr.io/aquasecurity/trivy-db:2|direct` and `docker.io/aquasec/trivy-db:2|direct` -> both passed over HTTP/2, TLS 1.3, anonymous token flow working. ghcr.io: total 1543ms (dns 218, tls 340, http 194, manifest 789). Docker Hub: total 2247ms (manifest 1330).
- Decisions / surprises: on this dev machine the connect stage takes about 0.3ms to reach GitHub and Docker Hub, so something local (VPN/TUN or transparent proxy) accepts TCP; the real network latency shows up in the TLS stage. This is expected on this network (owner). The direct route connects only to the first resolved address; this is an accepted limit (owner decision, see Decisions).
- Next: P3-1

### 2026-10-15  P2-6  Pre-check test matrix
- Status: done
- What changed: added `TestPrecheck_Hangs`: blackholed HTTP and SOCKS5 proxies fail at connect within the 100ms connect timeout; a registry that hangs on the manifest fails at the manifest timeout; the overall deadline (150ms) stops a TLS hang whose stage timeout is 1 minute; caller cancellation stops the check. The rest of the P2-6 list was already covered by P2-1 to P2-5: ok server, TLS failure, no HTTP/2 (with and without `allow-http1`), HTTP proxy, SOCKS5, redaction in results, errors and logs.
- Files: `pkg/v2/dbmgr/precheck_stages_test.go`
- Tests run: `go test -short -race -count=5 ./pkg/v2/dbmgr/` -> ok; coverage `pkg/v2/dbmgr` 83.9%, `pkg/v2/config` 100%
- Decisions / surprises: none
- Next: P2-7

### 2026-10-15  P2-5  Pre-check logging
- Status: done
- What changed: `Precheck` logs "DB source pre-check started" (source with masked proxy credentials, route, TLS minimum version, ALPN offered, allow_http1). Then one "DB source pre-check stage" line per stage (stage, ok, skipped, duration_ms, first_byte_ms, detail): INFO when it passed, WARN when it failed. Last comes "DB source pre-check passed" (INFO) or "... failed" (WARN). The stage lines are written in a defer once the check ends; every stage is time-bounded, so they appear within `PrecheckTimeoutTotal`.
- Files: `pkg/v2/dbmgr/precheck.go`, `pkg/v2/dbmgr/precheck_log_test.go`
- Tests run: `go test -short -race -count=3 ./pkg/v2/dbmgr/` -> ok; `go vet` -> ok. Log tests check line order and fields for a passing SOCKS5 check, WARN lines for an HTTP/1.1 rejection, and redaction: no proxy password, token, `user:`, `Authorization`, `Bearer` or `Basic` in any log line, including when the proxy rejects the credentials with 407.
- Decisions / surprises: durations are logged in whole milliseconds, so very fast local stages show 0; the exact values stay in `CheckResult`. The ERROR "all DB sources failed" line belongs to the fallback loop (P3-6).
- Next: P2-6

### 2026-10-15  P2-4  Pre-check timings
- Status: done
- What changed: `StageResult.FirstByte` holds the time to the first response byte for the http and manifest stages, measured with `httptrace.GotFirstResponseByte` (`withFirstByteTrace`). DNS, connect and TLS timings are the durations of those stages, and the total is `CheckResult.Duration`, so DEMAND 7.3 item 4 is covered without duplicating fields.
- Files: `pkg/v2/dbmgr/precheck.go`, `pkg/v2/dbmgr/precheck_stages_test.go`
- Tests run: `go test -short -race -count=5 ./pkg/v2/dbmgr/` -> ok (no data races); `go vet` -> ok. New checks: every stage has a duration, and first byte is set only on http and manifest and is not longer than the stage. A registry that delays the manifest by 100ms shows it in the manifest first byte only.
- Decisions / surprises: with the token flow, the manifest first byte is the first response of the stage (the 401), not the final manifest response. That matches "time until the registry answers".
- Next: P2-5

### 2026-10-15  P2-3  Pre-check stages
- Status: done
- What changed: `dbmgr.Precheck(ctx, source, cfg)` runs dns, connect, tls, http (`GET /v2/`) and manifest in order, stops at the first failure, and is bounded by `PrecheckTimeoutTotal`.
  - dns: direct route resolves the registry host and connects to the first address; proxy route records dns as skipped (owner decision).
  - tls: records version, cipher and ALPN.
  - http: fails when ALPN is not `h2` unless the source has `allow-http1`. Accepts 200 or 401 from `/v2/`, since 401 means the registry wants a token, which still proves it is a registry. Records protocol and status.
  - manifest: `GET /v2/<path>/manifests/<tag>`, with the anonymous Bearer token flow when the registry asks for it (ghcr.io, Docker Hub). Records protocol, status and `Docker-Content-Digest`.
  - The http and manifest stages reuse the exact TLS connection the earlier stages checked, handed to an `http.Transport` once. Other hosts (the token realm) get a new connection through the same route.
- Files: `pkg/v2/dbmgr/precheck.go`, `pkg/v2/dbmgr/registry.go` (repository parsing, TLS config, `dialTLS`, `getManifest`, `getToken`), `pkg/v2/dbmgr/precheck_stages_test.go`
- Tests run: `go test -short -race -count=10 ./pkg/v2/dbmgr/` -> ok; `make test` -> ok; `go vet` -> ok; `go.mod` unchanged. Fake TLS registry (HTTP/2 or HTTP/1.1, with or without token): direct HTTP/2, token flow, HTTP/1.1 rejected by default, HTTP/1.1 with `allow-http1`, manifest 404, untrusted certificate, blackholed registry stops at the TLS timeout, via HTTP proxy, via SOCKS5 with credentials. Neither the token nor the proxy password appears in the marshalled result.
- Decisions / surprises:
  - `docker.io` is mapped to `registry-1.docker.io` (the Docker Hub API host).
  - Registry TLS uses the system CA pool; tests swap the package variable `rootCAs`. Internal mirror CAs must be in the system pool (`SSL_CERT_FILE` / `SSL_CERT_DIR` work). Owner decision: no per-source CA option.
  - The token flow belongs to P3-1 but the manifest stage needs it now; P3-1 will reuse `getManifest` and `getToken`.
  - The tests caught a bug before commit: `Duration` was set in a defer on a non-named return value; fixed with a named return.
- Next: P2-4

### 2026-10-15  P2-2  Stage runner and result types
- Status: done
- What changed: `pkg/v2/dbmgr/precheck.go` has `StageResult` (stage, ok, skipped, duration, detail), `CheckResult` (redacted source, ok, started_at, duration, stages), and `runStage`, which gives each stage its own timeout inside the overall-deadline context and records the result. On failure the detail says whether the stage timeout or the overall deadline was hit.
- Files: `pkg/v2/dbmgr/precheck.go`, `pkg/v2/dbmgr/precheck_test.go`, `docs/direct-scan/DEMAND.md`
- Tests run: `go test -short -race ./pkg/v2/dbmgr/` -> ok; `go vet` -> ok
- Decisions / surprises: `runStage` calls the stage directly (no extra goroutine), so a stage must honour its context; every stage uses `DialContext`, `HandshakeContext` or a request with context. The JSON tags are there for the later `db_checks` documents and `/api/v2/db`.
- Next: P2-3

### 2026-10-15  P2-1  Route-aware dialer
- Status: done
- What changed: new package `pkg/v2/dbmgr` with `Dial(ctx, source, addr)`, which returns a plain TCP connection to `addr` directly, through an HTTP proxy (our own CONNECT exchange, `Proxy-Authorization: Basic` from the proxy URL userinfo), or through SOCKS5 (`golang.org/x/net/proxy`, user/password auth). TLS is left to the caller, so the pre-check can time the TLS stage separately and HTTP/2 negotiates normally over the tunnel. `ctx` bounds the whole dial, including the proxy handshake (`context.AfterFunc` expires the connection deadline for CONNECT; the SOCKS5 library honours `ctx` itself).
- Files: `pkg/v2/dbmgr/dial.go`, `pkg/v2/dbmgr/dial_test.go`
- Tests run: `go test -short -race ./pkg/v2/dbmgr/` -> ok (80.8% coverage); `make test` -> ok. Tests use in-process servers: echo target, CONNECT proxy, minimal SOCKS5 server, blackhole. Cases: direct, HTTP proxy with and without auth, 407, SOCKS5 with and without auth, wrong SOCKS5 auth, blackholed proxy stops at the 200ms deadline for both schemes, unreachable proxy. Redaction: no error contains the password, `user:` or `Basic `.
- Decisions / surprises: no new module (x/net was already required; `go.mod` unchanged). Our own CONNECT code instead of `http.Transport.Proxy`, so the pre-check and the download use the exact same dial path (DEMAND 7.5). With a proxy, the target host name is resolved by the proxy (SOCKS5 sends the name, CONNECT sends host:port).
- Next: P2-2

### 2026-10-15  P3-6  Partial: SCANNER_DB_SOURCES required when v2 is enabled
- Status: partial (only the startup check; the fallback loop and degraded mode are still to do in Phase 3)
- What changed: `GetConfig` returns "SCANNER_DB_SOURCES is required when SCANNER_V2_API_ENABLED is true" when v2 is enabled and the list is empty or blank (owner decision).
- Files: `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`, `docs/direct-scan/CHECKLIST.md`
- Tests run: `go test -short -race -cover ./pkg/v2/...` -> ok, 100.0%; `go vet` -> ok
- Decisions / surprises: `SCANNER_JAVA_DB_SOURCES` stays optional.
- Next: P2-1

### 2026-10-15  P1-4  Follow-up: allow-http1 source option
- Status: done
- What changed: `SCANNER_DB_SOURCES` entries accept an optional third field of `;`-separated options; `allow-http1` sets `DBSource.AllowHTTP1`. `String()` prints the option. An unknown or empty option is a parse error that names the option (options never hold secrets).
- Files: `pkg/v2/config/sources.go`, `pkg/v2/config/sources_test.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race -cover ./pkg/v2/...` -> ok, 100.0%; `go vet` -> ok
- Decisions / surprises: `repo|direct|` (empty options) is rejected rather than ignored, so a typo cannot silently drop an option.
- Next: P3-6 startup check, then P2-1

### 2026-10-15  DECISIONS  Second round of owner answers, history fixed
- Status: done
- What changed: recorded the decisions above; DEMAND 7.3 and 11 now have the HTTP/2 policy, the `allow-http1` option and the required `SCANNER_DB_SOURCES`; CHECKLIST P2-3, P9-1 and P11-6 reworded and P11-7 added; new commit rule in CLAUDE.md. History rewritten (nothing was pushed): rebased from `cd0de8d` with an edit stop at the P0-3, P0-4, P0-5 and P1-1 commits to write the correct `CHECKLIST.md` in each, then took the decisions commit's own version on the expected conflict. The final tree was identical to the old HEAD (`git diff` empty). The old history is kept on branch `backup/pre-history-fix`; delete it when no longer needed. All commit hashes from P0-3 onward changed.
- Files: `CLAUDE.md`, `docs/direct-scan/*`
- Tests run: not applicable
- Decisions / surprises: a plain `fixup!` commit would only have fixed the P0-3 commit; the P0-4, P0-5 and P1-1 commits each ticked an empty file, so each needed its own correct checklist.
- Next: P1-4 follow-up, then P2-1

### 2026-10-15  P1-5  Config unit tests
- Status: done
- What changed: no new code. The tests written with P1-1 to P1-4 already cover `pkg/v2/config` at 100% of statements: defaults, every env var, Mongo required only when enabled, bad bool and bad duration, `d` durations, fallback interval with WARN, source parsing, ordering, validation and redaction.
- Files: `docs/direct-scan/CHECKLIST.md`, `docs/direct-scan/PROGRESS.md`
- Tests run: `go test -short -cover ./pkg/v2/config/` -> ok, 100.0%; `make test` -> ok (all packages)
- Decisions / surprises: Phase 1 exit met: config tests pass, and v2 disabled changes nothing (`main.go` is not touched yet).
- Next: P2-1

### 2026-10-15  P1-4  DB sources parser
- Status: done
- What changed: `config.ParseDBSources` parses `repo|route,repo|route` (route `direct`, `http://host:port`, `socks5://host:port`), keeping the order. `Config.DBSources` and `Config.JavaDBSources` are `[]DBSource`, parsed in `GetConfig`. `DBSource.String()` prints `repo|route` with the proxy userinfo replaced by `xxxxx`; the `Proxy` field keeps the real URL for the dialer.
- Files: `pkg/v2/config/sources.go`, `pkg/v2/config/sources_test.go`, `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race ./pkg/v2/...` -> ok (includes redaction tests: `String()` and parse errors never contain the proxy user or password); `go vet` -> ok; `go build ./...` -> ok
- Decisions / surprises: parse errors only give the 1-based source position and the expected format, never the raw value (`url.Parse` errors would echo the URL with its password). A repository containing `://` is rejected. An empty `SCANNER_DB_SOURCES` is allowed for now; whether v2 should refuse to start without any DB source is an open question for P3-6 (the seed DB would then never be updated).
- Next: P1-5

### 2026-10-15  P1-3  Duration parser and fallback interval
- Status: done
- What changed: `config.ParseDuration` accepts Go durations plus whole days (`1d`, `7d`). `Config.DBCheckInterval` is now a `time.Duration` read by `GetConfig`; when it is unset, invalid, zero or negative, it is 3h (`FallbackDBCheckInterval`) and a WARN "using fallback interval" is logged with the raw value.
- Files: `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race ./pkg/v2/...` -> ok (includes a log capture test for the WARN line); `go vet` -> ok; `go build ./...` -> ok
- Decisions / surprises: days must be whole and alone (`1d2h` and `1.5d` are rejected), the simplest reading of the spec. Only `SCANNER_DB_CHECK_INTERVAL` uses the `d` parser; other durations keep the standard Go format. Open point for P9-1: the WARN is logged even when v2 is disabled; when wiring `main.go`, only call `GetConfig` with v2 enabled, or move the interval block under `if cfg.Enabled`.
- Next: P1-4

### 2026-10-15  P1-2  v2 config struct
- Status: done
- What changed: `pkg/v2/config.Config` now has every variable from DEMAND section 11 with the owner's defaults. `SCANNER_MONGO_URI` and `SCANNER_MONGO_DB` are checked only when v2 is enabled; a missing one returns a clear error. `SCANNER_DB_CHECK_INTERVAL`, `SCANNER_DB_SOURCES` and `SCANNER_JAVA_DB_SOURCES` are kept as raw strings until P1-3 and P1-4 parse them.
- Files: `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race ./pkg/v2/...` -> ok; `go vet ./pkg/v2/...` -> ok; `go build ./...` -> ok
- Decisions / surprises: parse errors from `caarlos0/env` name the struct field (for example `ScanTimeout`), not the env var; kept as is, same as `pkg/etc`. Registry settings and the auth token are not required yet; validation comes with their users (P6-1, P9-1). The config must never be logged as a whole, because it holds the registry password, the auth token and possibly Mongo credentials in the URI.
- Next: P1-3

### 2026-10-15  P0-6  Baseline green
- Status: done
- What changed: updated tests for the `vendor_attributes.Trivy` addition from `0c87038` (owner chose KEEP). Unit fixture now has `"Type": "alpine"`, so Target and Type copying is actually tested. Integration test checks the exact image target; for the SBOM it checks the suffix only, because the target is a random temp file path. AC11 reworded in DEMAND and CHECKLIST.
- Files: `pkg/trivy/wrapper_test.go`, `pkg/scan/transformer_test.go`, `test/integration/api/rest_api_test.go`, `docs/direct-scan/*`
- Tests run: `make test` -> ok (all packages); `go test -count=1 -tags=integration ./test/integration/...` -> ok; `go vet ./...` and with integration tag -> ok. Component tests and lint not run.
- Decisions / surprises: test-only change; no production code touched.
- Next: P1-2

### 2026-10-15  DECISIONS  Owner answers on settings and DB download
- Status: done
- What changed: DEMAND bumped to v0.5 (sections 7.3, 7.4, 11); CHECKLIST gained P0-6 and P10-5, and P1-4 and P3-3 were reworded; decisions recorded above.
- Files: `docs/direct-scan/DEMAND.md`, `docs/direct-scan/CHECKLIST.md`, `docs/direct-scan/PROGRESS.md`
- Tests run: not applicable
- Decisions / surprises: the keep/revert choice for `vendor_attributes.Trivy` was left as a placeholder in the owner's message; asked again.
- Next: P0-6

### 2026-10-15  CORRECTION  CHECKLIST.md was emptied
- Status: done
- What changed: a script bug in the P0-3 commit (old hash `1a58c56`) truncated `CHECKLIST.md` (opened for writing before reading). Restored it from `cd0de8d` and re-ticked P0-3, P0-4, P0-5 and P1-1. (Later the history was rewritten so the file is never empty in any commit; see the second DECISIONS entry.) Later doc edits use a read-then-write helper that asserts each match.
- Files: `docs/direct-scan/CHECKLIST.md`
- Tests run: not applicable
- Decisions / surprises: none
- Next: P0-6

### 2026-10-15  P1-1  v2 feature flag
- Status: done
- What changed: new package `pkg/v2/config` with `Config.Enabled` (`SCANNER_V2_API_ENABLED`, default false) and `GetConfig()`, same `caarlos0/env` pattern as `pkg/etc`.
- Files: `pkg/v2/config/config.go`, `pkg/v2/config/config_test.go`
- Tests run: `go test -short -race ./pkg/v2/...` -> ok; `go vet ./pkg/v2/...` -> ok; `go build ./...` -> ok
- Decisions / surprises: `main.go` is not touched yet. Nothing exists to wire, so the flag is read in `main.go` together with the `/api/v2` mount in P9-1. Until then v2 is off in every case, which satisfies "off by default".
- Next: P1-2

### 2026-10-15  P0-5  Commands in CLAUDE.md
- Status: done
- What changed: filled section 4 (Commands) of `CLAUDE.md`.
- Files: `CLAUDE.md`, `docs/direct-scan/PROGRESS.md`, `docs/direct-scan/CHECKLIST.md`
- Tests run: not applicable (commands were run in P0-2)
- Decisions / surprises: none
- Next: P1-1

### 2026-10-15  P0-4  Mongo test strategy and libraries
- Status: done
- What changed: chose the Mongo driver, SOCKS5 library and Mongo test strategy; recorded under "Decisions".
- Files: `docs/direct-scan/PROGRESS.md`, `docs/direct-scan/CHECKLIST.md`
- Tests run: not applicable
- Decisions / surprises: SOCKS5 needs no new module. Mongo tests reuse the testcontainers pattern already used for Redis.
- Next: P0-5

### 2026-10-15  P0-3  Package layout confirmed
- Status: done
- What changed: confirmed the `pkg/v2/...` layout and the wiring point; recorded under "Decisions".
- Files: `docs/direct-scan/PROGRESS.md`, `docs/direct-scan/CHECKLIST.md`
- Tests run: not applicable
- Decisions / surprises: only `main.go` needs touching to mount `/api/v2`; the readiness probe will need one more touch later (P10-2).
- Next: P0-4

### 2026-10-15  P0-2  Baseline build and tests
- Status: done (baseline recorded; it is not green)
- What changed: ran build, vet, unit and integration tests; recorded commands and results under "Repo facts".
- Files: `docs/direct-scan/PROGRESS.md`, `docs/direct-scan/CHECKLIST.md`
- Tests run: `go build ./...` -> ok; `go vet ./...` -> ok; `make test` -> FAIL (TestWrapper_Scan, TestTransformer_Transform); `go test -tags=integration ./test/integration/...` -> FAIL (TestRestAPI), redis ok; same `./pkg/...` tests on upstream `2691434` -> all ok. Component tests and lint not run.
- Decisions / surprises: the failures come from our own earlier commit `0c87038`, not from upstream. Left untouched; question raised to the owner (see Current state).
- Next: P0-3

### 2026-10-15  P0-1  Repo facts recorded
- Status: done
- What changed: filled package map, Go version, logger and config pattern, Trivy invocation, Trivy version and CI under "Repo facts".
- Files: `docs/direct-scan/PROGRESS.md`, `docs/direct-scan/CHECKLIST.md`
- Tests run: not applicable (reading only)
- Decisions / surprises: Trivy runs with no Go-side timeout or kill (only `--timeout`); the v2 runner (P7-1) must add `exec.CommandContext`. Lint uses golangci-lint v1.21.0 from `make setup`, which is too old for Go 1.26.
- Next: P0-2

### 2026-10-15  CORRECTION  Docs location and earlier upstream changes
- Status: done
- What changed: the planning docs were at the repo root (untracked), not in `docs/direct-scan/` as this file and `CLAUDE.md` say. Moved them to `docs/direct-scan/`. Commits `0c87038` and `f917cc0` changed upstream files and were not mentioned anywhere; they are now listed under "Upstream files touched". Added the "boring, simple code" rule to `CLAUDE.md` section 2 (asked by the owner).
- Files: `CLAUDE.md`, `docs/direct-scan/*`
- Tests run: not applicable
- Decisions / surprises: see P0-2 for the test failures these earlier commits cause.
- Next: P0-1

### 2026-10-14  PLAN  Planning documents created
- Status: done
- What changed: created `CLAUDE.md`, `docs/direct-scan/DEMAND.md`, `PLAN.md`, `CHECKLIST.md`, `PROGRESS.md`. No code yet.
- Files: the five files above
- Tests run: not applicable
- Decisions / surprises: none
- Next: P0-1
