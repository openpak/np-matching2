# Multi-stage, cross-compiled: the build stage runs on the runner's native arch and Go
# emits the target arch, so linux/arm64 builds need no QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/np-matching2 ./cmd/np-matching2

FROM alpine:3.22
LABEL org.opencontainers.image.source="https://github.com/openpak/np-matching2"
RUN addgroup -S app && adduser -S -G app app
USER app
COPY --from=build /out/np-matching2 /usr/local/bin/np-matching2
EXPOSE 8538 8443 3480
ENTRYPOINT ["/usr/local/bin/np-matching2"]
