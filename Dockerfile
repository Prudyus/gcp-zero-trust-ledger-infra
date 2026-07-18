# syntax=docker/dockerfile:1
###############################################################################
# Dockerfile — multi-stage, unprivileged production image for ledger-api (Go)
#
# Assumed app layout (Go service, conventional module structure):
#   go.mod / go.sum
#   cmd/server/main.go → HTTP server on $PORT (8080): /healthz /readyz /metrics
#   (clients: cloud.google.com/go/spanner with SessionPoolConfig DatabaseRole
#    = SPANNER_DATABASE_ROLE; Vault transit for PII fields — env contract in
#    kubernetes/apps/ledger-api/deployment.yaml)
#
# Contract with the Deployment (Module 3):
#   * UID:GID 10001:10001 → matches pod securityContext runAsUser/runAsGroup
#   * static binary, nothing writes to the FS → readOnlyRootFilesystem: true
#     (emptyDir mounted at /tmp for scratch)
#   * /bin/sh present     → required by the preStop "sleep 5" hook; this is
#     the deliberate reason for an Alpine runtime over distroless
#   * ca-certificates     → TLS to Spanner/googleapis via the private VIP
#   * listens on 8080     → containerPort / probes
#
# Build runs on GitHub runners (internet available); the RESULT is pushed
# into Artifact Registry, the only source Binary Authorization admits into
# the cluster. Unit tests run in the app's own CI job, not the image build.
# Production hardening backlog: pin both base images by digest (Renovate
# keeps digests current while staying readable).
###############################################################################

# =============================================================================
# Stage 1 — build: static, reproducible-leaning Go binary
# =============================================================================
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Dependency layer first: re-resolved only when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown

# CGO off → fully static binary (no libc dependency in the runtime image).
# -trimpath + -s -w: strip local paths and debug symbols (smaller, no
# host-path leakage). Version metadata is injected, not baked in files.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/ledger-api ./cmd/server

# =============================================================================
# Stage 2 — runtime: minimal Alpine, dedicated non-root user (10001)
# =============================================================================
FROM alpine:3.21 AS runtime

ARG VERSION=dev
ARG COMMIT=unknown

LABEL org.opencontainers.image.title="ledger-api" \
      org.opencontainers.image.source="https://github.com/acme/ledger-platform" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.vendor="acme"

# ca-certificates: outbound TLS (Spanner/googleapis, Vault via mesh).
# tzdata: correct zone handling for audit timestamps.
# System (-S) user: no password entry, no home (-H), no login shell.
# Version pinning of apk packages is intentionally skipped (breaks builds as
# Alpine rotates patch versions); Trivy gates the result in CI instead.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 10001 -S app && \
    adduser  -u 10001 -S -G app -H -s /sbin/nologin app

COPY --from=build /out/ledger-api /usr/local/bin/ledger-api

# Numeric USER (not name) so the Kubernetes runAsNonRoot validation can
# verify the UID without inspecting /etc/passwd.
USER 10001:10001

ENV PORT=8080
EXPOSE 8080

# No HEALTHCHECK instruction: Kubernetes probes own health, and a Docker
# healthcheck would just burn cycles under kubelet.
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/ledger-api"]