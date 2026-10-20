# Direct scan API (v2): operator guide

This fork adds a direct scan API (`/api/v2`) next to the Harbor adapter (`/api/v1`). The design and every setting are in [DEMAND.md](DEMAND.md) (section 11 lists all variables); this page covers running it.

## Enable it

- `SCANNER_V2_API_ENABLED=true`. With it unset or false, nothing changes: the Harbor adapter runs as before and none of the settings below are read or checked.
- Required when enabled: `SCANNER_V2_AUTH_TOKEN` (at least 32 characters), `SCANNER_MONGO_URI`, `SCANNER_MONGO_DB`, `SCANNER_DB_SOURCES`, `SCANNER_REGISTRY_URL`. Startup fails with a clear error when one is missing.
- Set `SCANNER_INSTANCE_ID` explicitly per replica (for example `scanner-1`), so an instance keeps its DB state when its container is recreated. The default is the hostname, with a WARN.
- Callers send `Authorization: Bearer <SCANNER_V2_AUTH_TOKEN>` on every `/api/v2/...` request. `/probe/healthy` and `/probe/ready` need no token.

## Network and credentials

- DB sources (`SCANNER_DB_SOURCES`, `SCANNER_JAVA_DB_SOURCES`), tried in order: our own mirror first, Docker Hub (`docker.io/aquasec/trivy-db:2`, `docker.io/aquasec/trivy-java-db:1`) as the fallback. Do not use ghcr.io: on our network long transfers from it are reset after minutes (the source fails with `stream_reset` and the next one is tried). Keep the real mirror address in `.env` only. A mirror that speaks only HTTP/1.1 fails the pre-check (`http2_not_negotiated`) unless its entry has the `allow-http1` option: `mirror.example.internal/aquasecurity/trivy-db:2|direct|allow-http1`.

- DNS: set the DNS servers with Docker's `dns:` setting (or the host's `/etc/resolv.conf`). Go's resolver tries them in order; the scanner has no DNS pool of its own.
- Harbor robot account names contain `$` (for example `robot$scanner`). Docker Compose interpolates `$` in `docker-compose.yaml` and in `env_file` values, so write `robot$$scanner`; an unescaped `robot$scanner` reaches the container as `robot` (checked with Compose 5.6). In a shell, quote it: `'robot$scanner'`.
- Keep secrets (`SCANNER_V2_AUTH_TOKEN`, `SCANNER_REGISTRY_PASSWORD`, the MongoDB password in `SCANNER_MONGO_URI`) in a `.env` file with mode 0600, never in the image or the compose file. The scanner never logs them, never puts them on Trivy's command line (Trivy gets the robot account through `TRIVY_USERNAME`/`TRIVY_PASSWORD`), and never stores them in MongoDB.
- MongoDB write and read concern are set in `SCANNER_MONGO_URI` (for example `w=majority&readConcernLevel=majority`). The scanner uses no multi-document transactions. MongoDB 4.2 or newer is required; the examples use 7. Give MongoDB a high open-file limit (`nofile` 64000), a persistent volume and authentication.
- `/metrics` (Prometheus) is served on the same port without authentication. Keep that port internal.

## Memory and disk

- `SCANNER_V2_CACHE_DIR` (default `/home/scanner/.cache/scanner-v2`) holds the v2 Trivy DB and Java DB (version directories), the workers' Trivy layer caches and one temp directory per running scan. Put it on a persistent local SSD volume, not on network storage. Do not use tmpfs: the DB stays on disk, and the operating system's page cache keeps it in RAM whenever the machine has free memory, so extra RAM speeds scans up without any setting.
- The Harbor adapter (v1) keeps its own Trivy DB in `SCANNER_TRIVY_CACHE_DIR`, so a replica has two DB copies on disk.
- Each scan gets its own temp directory inside `SCANNER_V2_CACHE_DIR` (Trivy's `TMPDIR` and its output). It is removed when the scan ends, whether it succeeded, failed, timed out or was killed, and leftovers of a crash are removed at startup. There is no separate temp-dir setting.
- Worker layer cache, `SCANNER_V2_WORKER_CACHE_BACKEND`:
  - `fs` (default): each worker keeps Trivy's layer cache on disk and reuses it across scans, so a second image that shares base layers is much faster. `SCANNER_V2_WORKER_CACHE_MAX` (default `5GB` per worker) is a safety net: between scans, a worker whose layer cache is larger clears it (never the DB).
  - `memory`: nothing of the layer cache is written to disk. The in-memory cache lives for one scan only (one Trivy process per scan), so every scan analyzes all layers again. Trivy 0.74.0 accepts `--cache-backend memory` although its `--help` does not list it; recheck it when Trivy is upgraded.

## Sizing

Measured on 2026-10-20 with Trivy 0.74.0 (details in PROGRESS.md, task P11-12).

| What | Size |
|---|---|
| Trivy DB download (compressed layer) | 129 MiB |
| Trivy DB on disk (`trivy.db` + `metadata.json`) | 1.53 GiB |
| Java DB download (compressed layer) | 940 MiB |
| Java DB on disk (`trivy-java.db` + `metadata.json`) | 1.45 GiB |
| Worker layer cache (`fs`), after two Debian-based images | about 2 MiB |
| Scan temp directory, peak per running scan | about the largest image layer (118 MiB for `node:22-bookworm`) |
| Trivy memory (peak RSS) per running scan | 290-360 MiB for a 392 MiB image (`node:22-bookworm`), both backends |

Disk per replica (`SCANNER_V2_CACHE_DIR` on a persistent local SSD):

- Trivy DB x3 (current, previous, the one being installed): about 4.6 GiB.
- Java DB x3, only when `SCANNER_JAVA_DB_SOURCES` is set: about 4.4 GiB.
- The Harbor adapter's own DB copy in `SCANNER_TRIVY_CACHE_DIR`: 1.53 GiB (plus its Java DB if it uses one).
- Worker layer caches (`fs` backend): small in practice, capped by `SCANNER_V2_WORKER_CACHE_MAX` (5GB) per worker.
- Temp space: the largest layer of the images being scanned, per worker.

Each DB install writes one full DB (1.53 GiB for the Trivy DB, 1.45 GiB for the Java DB). Upstream rebuilds the Trivy DB about every 6 hours, so with `SCANNER_DB_CHECK_INTERVAL=3h` expect up to about four installs a day.

Memory: about 2 GB per worker plus 1 GB for the service (`mem_limit: 5g` for 2 workers). Measured peaks next to that: 293-358 MiB of Trivy RSS per scan of a 392 MiB image (table below). Larger images, Java analysis and the scanner's own buffers add to it; lower the limit only after watching real scans. Free memory beyond the limit is still useful: the page cache keeps the DB files in RAM.

Measured scans (empty worker cache for each backend; the second image shares 4 of its 7 layers with the first):

| Backend | Image (compressed) | Time | Peak Trivy RSS | Peak temp dir | Layer cache after |
|---|---|---|---|---|---|
| fs | node:22-bookworm (392 MiB) | 53 s | 293 MiB | 118 MiB | 2 MiB |
| fs | python:3.12-bookworm (365 MiB) | 8 s | 300 MiB | 0 | 2 MiB |
| memory | node:22-bookworm | 47 s | 358 MiB | 116 MiB | none |
| memory | python:3.12-bookworm | 54 s | 336 MiB | 0 | none |

`fs` is the default: an image that shares base layers with one scanned before is much faster, and it used less memory. `memory` stays an option when nothing of the layer cache may be written to disk.

## Compose example

[compose/docker-compose.yaml](compose/docker-compose.yaml) runs two scanner replicas and MongoDB 7: an explicit `SCANNER_INSTANCE_ID` per replica, `stop_grace_period: 45s` (longer than `SCANNER_SHUTDOWN_GRACE`, 30s, so running scans can finish or be released), `dns:`, a healthcheck on `/probe/ready`, the image's non-root user, a memory limit, and the secrets in `.env` ([compose/.env.example](compose/.env.example)). The hostnames and DNS addresses in it are placeholders.
