# Clean app: latest Go patch release + distroless static (no shell, no package manager).
# The build stage runs natively on each runner's own architecture (no emulation).
FROM golang:1.27.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/orders .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/orders /orders
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/orders"]
