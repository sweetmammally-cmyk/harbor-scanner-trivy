# PROGRESS: state and changelog

Claude Code: read this file FIRST in every session, and update it after every task (see `CLAUDE.md` section 3).
Newest changelog entries go at the top of the Changelog.

## Current state

- Phase: 1
- Last completed task: P1-1
- In progress: none
- Next task: P1-2 (waiting on owner: env var names and defaults not in DEMAND section 11, see Blockers)
- Blockers / questions for the user:
  - P1-2 / P1-4: DEMAND section 11 gives no defaults (workers, queue length, scan timeout, download timeout, max DB age, Mongo DB name), no names for the `SCANNER_PRECHECK_TIMEOUT_*` variables, and no format for `SCANNER_DB_SOURCES`. Need the owner's answers before coding.
  - Baseline has 3 failing tests caused by commit `0c87038` (Harbor report now carries `vendor_attributes.Trivy`). Owner must choose: keep the change and update the tests, or revert it. Also: the INFO-level "FULL TRIVY REPORT" dump in `pkg/trivy/wrapper.go` looks like leftover debug code.
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
- Baseline test result before our changes (2026-10-15, HEAD `3d447af`, code same as `f917cc0`):
  - `go build ./...`: OK. `go vet ./...`: OK.
  - `make test`: **FAIL**. `TestWrapper_Scan` (pkg/trivy) and `TestTransformer_Transform` (pkg/scan) fail; everything else passes. Cause: commit `0c87038` added `Vulnerability.Target/Type` and the `Trivy` vendor attribute without updating tests. On upstream `2691434` all `./pkg/...` tests pass (checked in a temporary worktree).
  - `make test-integration`: **FAIL** in `test/integration/api` (`TestRestAPI`: Harbor report now has `vendor_attributes.Trivy`, same cause). `test/integration/persistence/redis`: OK.
  - `make test-component`: not run (needs a full image build; slow).
  - `make lint`: not run (golangci-lint not installed; pinned v1.21.0 is too old for Go 1.26).

## Decisions

Record decisions here with date and reason (package layout, Mongo test strategy, OCI client approach, DB swap mechanism, anything the user answered). If a decision changes the spec, also propose the edit to `DEMAND.md`.

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
