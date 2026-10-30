# syntax=docker/dockerfile:1
ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/app .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=build /out/app /usr/local/bin/app
# intentionally leaked for the demo: forge must block the push
COPY config.yaml /etc/app/config.yaml
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/app"]
