# Multi-arch the fast way: the build stage runs NATIVELY ($BUILDPLATFORM) and
# cross-compiles for $TARGETARCH; only the small runtime stage runs per target
# (its RUN is emulated with QEMU when the target is a foreign architecture).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/app .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && echo "built on $(uname -m)" > /etc/forge-arch
COPY --from=build /out/app /usr/local/bin/app
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/app"]
