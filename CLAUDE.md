# CLAUDE.md: harbor-scanner-trivy (direct scan API fork)

This repo is our fork of `goharbor/harbor-scanner-trivy`. We are adding a direct scan API (`/api/v2`), a MongoDB data plane, a scan cache, our own Trivy DB download module with pre-checks, a queue and health endpoints.

## 1. Session start protocol (do this EVERY time, before any code)

1. Read, in this order:
   1. `docs/direct-scan/PROGRESS.md`: the "Current state" block and the newest changelog entries. This is your memory.
   2. `docs/direct-scan/CHECKLIST.md`: which tasks are done, which one is in progress, what is next.
   3. `docs/direct-scan/PLAN.md`: the phase you are in (read the other phases only when needed).
   4. `docs/direct-scan/DEMAND.md`: the spec and source of truth. Read the sections relevant to the current task.
2. Recover state: run `git status`, `git log --oneline -15`, and `git diff --stat`. Compare with PROGRESS.md.
   - If they agree: continue.
   - If code exists that PROGRESS.md does not mention, or PROGRESS.md claims work git does not show: **trust git**, then add a "Correction" entry to PROGRESS.md explaining the difference.
   - If a task is marked `IN PROGRESS`, inspect its files and finish or redo it before starting anything new.
3. Tell the user a short summary before coding: current phase, last completed task, the task you will do now, and any drift or blockers.

## 2. Working rules

- Write boring, simple, and maintainable code. Prefer existing patterns, basic syntax, and straightforward logic. Avoid unnecessary abstractions, new functions, helpers, classes, dependencies, or clever tricks. Make the smallest possible change and reuse existing code where appropriate. Preserve code ownership and ensure the implementation can be fully understood and reviewed by a human in a single pass.
- Work on **one checklist task at a time**. Small, reviewable commits, one task per commit where possible. Commit message starts with the task ID, for example `P2-3: add TLS handshake stage`.
- The spec is `DEMAND.md`. Do not silently change behaviour. If the spec is ambiguous or you think it is wrong, stop and ask the user; record the answer in the PROGRESS.md "Decisions" section and propose the edit to `DEMAND.md`.
- Do **not** implement deferred items (digest store collection, multi-architecture handling, queue priorities, Trivy analyzer-level restriction). They are listed in `DEMAND.md` section 14.
- Harbor adapter endpoints (`/api/v1/...`, probes) must keep working exactly as before. Keep new code in the package layout recorded in PLAN.md (default: `pkg/v2/...`). Touch upstream files only when unavoidable, and list every such touch in PROGRESS.md (it keeps future upstream merges easy).
- Every network operation takes a `context.Context` with a timeout. Nothing may hang without a deadline.
- Never log, print, store in MongoDB or pass on the command line: registry credentials, service tokens, `Authorization` headers. Pass Trivy credentials through the environment. Add a redaction test whenever you add logging near secrets.
- Use the repo's existing logger and error-handling style. Wrap errors with context.
- Every task needs tests. Run the build and tests before marking a task done. If you cannot run something, say so in PROGRESS.md; never claim it passed.
- MongoDB is a hard dependency of the v2 service: no silent fallbacks around it.

## 3. After EVERY task (this is how state survives)

1. Tick the task in `CHECKLIST.md` (`[x]`). If you stop mid-task, mark it `[~]` (in progress) and say where you stopped.
2. Add an entry at the top of the Changelog in `PROGRESS.md` using the entry template there.
3. Update the "Current state" block in `PROGRESS.md` (phase, last done, in progress, next, blockers).
4. Commit code and these doc updates together.

When the context is getting long, or the user ends the session, write a handoff note first: update "Current state" so a fresh session can continue with no other information.

## 4. Commands

```
build:             go build ./...            (binary: make build)
test:              make test                 (unit, -short -race, no Docker)
one package:       go test -short ./pkg/v2/config/...
integration:       make test-integration     (build tag integration, needs Docker: Redis, Mongo, registry)
component:         make test-component       (builds the Docker image; slow)
vet:               go vet ./...
lint:              make lint                 (needs ./bin/golangci-lint; not installed locally, the pinned v1.21.0 is too old for Go 1.26)
```

Baseline is not fully green: see PROGRESS.md "Repo facts" for the known failing tests. Do not count those as regressions, and do not count new failures as baseline.

## 5. Quick map

| File | Purpose |
|---|---|
| `docs/direct-scan/DEMAND.md` | Requirements (source of truth) |
| `docs/direct-scan/PLAN.md` | Phased implementation plan |
| `docs/direct-scan/CHECKLIST.md` | Task checklist with IDs |
| `docs/direct-scan/PROGRESS.md` | State and changelog (read first, write after every task) |
