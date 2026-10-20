# That's the only place where you're supposed to specify version of Trivy.
ARG TRIVY_VERSION=0.74.0
ARG SKAFFOLD_GO_GCFLAGS

FROM golang:1.26 AS builder

# Go module proxy for the build; override with --build-arg GOPROXY=... (for
# example a regional mirror). The Makefile passes GOPROXY from the environment.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=off

WORKDIR /go/src/github.com/aquasecurity/harbor-scanner-trivy

# Download Go dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project and build it.
COPY cmd/ ./cmd
COPY pkg/ ./pkg
RUN CGO_ENABLED=0 go build -gcflags="${SKAFFOLD_GO_GCFLAGS}" -o scanner-trivy cmd/scanner-trivy/main.go

FROM aquasec/trivy:${TRIVY_VERSION}

ENV GOTRACEBACK=all

# An ARG declared before a FROM is outside of a build stage, so it can't be used in any
# instruction after a FROM. To use the default value of an ARG declared before the first
# FROM use an ARG instruction without a value inside of a build stage.
ARG TRIVY_VERSION

RUN adduser -u 10000 -D -g '' scanner scanner

# The v2 service's DBs, worker layer caches and per-scan temp directories
# (SCANNER_V2_CACHE_DIR). Mount a persistent local volume here; the directory
# exists with the right owner so a new named volume inherits it.
RUN mkdir -p /home/scanner/.cache/scanner-v2 && chown -R scanner:scanner /home/scanner/.cache

# Seed DB for offline installs (v2, SCANNER_DB_SEED_DIR): the default image has
# none. Build with --build-arg WITH_SEED_DB=true to bake the Trivy DB in;
# SEED_DB_REPOSITORY picks where it is downloaded from (for example our mirror).
ARG WITH_SEED_DB=false
ARG SEED_DB_REPOSITORY=docker.io/aquasec/trivy-db:2
RUN if [ "$WITH_SEED_DB" = "true" ]; then \
      trivy image --download-db-only --no-progress --db-repository "$SEED_DB_REPOSITORY" --cache-dir /tmp/seed-cache && \
      mkdir -p /home/scanner/seed/db && \
      cp /tmp/seed-cache/db/trivy.db /tmp/seed-cache/db/metadata.json /home/scanner/seed/db/ && \
      rm -rf /tmp/seed-cache && \
      chown -R scanner:scanner /home/scanner/seed; \
    fi

COPY --from=builder /go/src/github.com/aquasecurity/harbor-scanner-trivy/scanner-trivy /home/scanner/bin/scanner-trivy

ENV TRIVY_VERSION=${TRIVY_VERSION}

USER scanner

ENTRYPOINT ["/home/scanner/bin/scanner-trivy"]
