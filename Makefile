BINARY := codecrucible
MODULE := github.com/block/codecrucible
CMD    := ./cmd/codecrucible

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -X '$(MODULE)/internal/cli.version=$(VERSION)' \
           -X '$(MODULE)/internal/cli.commit=$(COMMIT)' \
           -X '$(MODULE)/internal/cli.date=$(DATE)'

.PHONY: build test lint clean coverage docker-build docker-test fmt vet

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

test:
	go test -race -count=1 ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, running go vet"; \
		go vet ./...; \
	fi

coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out
	@echo "---"
	@echo "HTML report: go tool cover -html=coverage.out -o coverage.html"

fmt:
	gofmt -w .

vet:
	go vet ./...

docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(BINARY):$(VERSION) \
		-t $(BINARY):latest .

docker-test:
	docker run --rm $(BINARY):latest --version

clean:
	rm -f $(BINARY) coverage.out coverage.html
