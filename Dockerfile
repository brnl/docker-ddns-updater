# syntax=docker/dockerfile:1

# Base images are pinned by digest; Dependabot keeps tags and digests current.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/ddns-updater ./cmd/ddns-updater

# Distroless "static": no shell, no package manager, only CA certificates,
# tzdata and /etc/passwd. Runs as the unprivileged "nonroot" user (65532).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
ARG VERSION=dev
LABEL org.opencontainers.image.title="ddns-updater" \
      org.opencontainers.image.description="Monitors the public IP address and updates DDNS records (mijn.host) when it changes" \
      org.opencontainers.image.source="https://github.com/brnl/docker-ddns-updater" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/ddns-updater /ddns-updater
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/ddns-updater", "healthcheck"]
ENTRYPOINT ["/ddns-updater"]
