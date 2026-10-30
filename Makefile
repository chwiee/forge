VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X github.com/chwiee/forge/internal/cli.Version=$(VERSION)
GOARCH  ?= amd64

.PHONY: build test vet fmt clean

build:
	GOOS=linux GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/forge ./cmd/forge

test:
	go test ./...

vet:
	GOOS=linux go vet ./...

fmt:
	gofmt -w ./cmd ./internal

clean:
	rm -rf bin .out .forge
