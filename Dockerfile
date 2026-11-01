# syntax=docker/dockerfile:1
#
# ShieldMon container image (docs/adr/0012-container-image.md): distroless, non-root, read-only
# root filesystem, scanners pinned by SHA-256. Builds linux/amd64 and linux/arm64 without
# emulation: the build stages run on the build platform and cross-compile or download for the
# target. Base images are pinned by digest; Renovate keeps them current.

FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/nocs90/shieldmon/internal/cli.Version=${VERSION}" \
      -o /out/shieldmon ./cmd/shieldmon

FROM --platform=$BUILDPLATFORM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS scanners
ARG TARGETOS TARGETARCH
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends bash ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY scripts/install-scanners.sh /install-scanners.sh
# Checksums are recorded in the script, not fetched, and each release's signed checksums are
# verified with a pinned cosign (ADR 0006): a bad download or signature fails the build.
RUN /install-scanners.sh /out "$TARGETOS/$TARGETARCH" && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/shieldmon /usr/local/bin/shieldmon
COPY --from=scanners /out/ /usr/local/bin/
COPY --from=scanners --chown=65532:65532 /data /data
# Everything ShieldMon and its scanners write goes under /data: the root filesystem can be
# read-only. The config is read from /config/shieldmon/config.yaml when mounted; without it
# the built-in defaults apply, including scanners.sandbox.backend: auto (landlock here).
ENV XDG_CONFIG_HOME=/config \
    TMPDIR=/data/tmp
VOLUME ["/data"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/shieldmon", "--data-dir", "/data"]
CMD ["monitor"]
