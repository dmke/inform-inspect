GO ?= go
GOLANGCI_LINT ?= golangci-lint

.PHONY: all
all: lint test

.PHONY: build
build:
	$(GO) build ./...

.PHONY: test
test:
	$(GO) test -race -cover ./...

.PHONY: lint
lint:
	$(GOLANGCI_LINT) run

.PHONY: fmt
fmt:
	$(GOLANGCI_LINT) fmt

.PHONY: tidy
tidy:
	$(GO) mod tidy
