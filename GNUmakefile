GOLANGCI_LINT = github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 # keep in sync with CI

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z_-]+:.*## / { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: all
all: lint test ## Run lint and test

.PHONY: build
build: ## Compile all packages (writes no binaries)
	go build ./...

.PHONY: test
test: ## Run tests with the race detector and print coverage per package
	go test -race -cover ./...

.PHONY: lint
lint: ## Run golangci-lint
	go run $(GOLANGCI_LINT) run

.PHONY: fmt
fmt: ## Format code with gofmt and goimports (rewrites files in place)
	go run $(GOLANGCI_LINT) fmt

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	go mod tidy
