# PROGRESS: state and changelog

Claude Code: read this file FIRST in every session, and update it after every task (see `CLAUDE.md` section 3).
Newest changelog entries go at the top of the Changelog.

## Current state

- Phase: 3 (DB download module)
- Last completed task: P3-7
- In progress: P3-9 (`[~]`): the real ghcr.io download is done and recorded; the fake-registry cases are mostly covered by the P3-3 and P3-6 tests; fill the gaps next
- Next task: finish P3-9, then Phase 4
- Blockers / questions for the user: none
- Last updated: 2026-10-15

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
- Trivy version pinned: `TRIVY_VERSION=0.74.0` in `Dockerfile` and in `make setup`. The local dev machine has trivy 0.71.2 on PATH.
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
