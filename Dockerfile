# syntax=docker/dockerfile:1

# Base images are pinned by digest; Dependabot keeps tags and digests current.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
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
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
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
