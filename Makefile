# probe — build & dev automation
SHELL := /bin/bash
.DEFAULT_GOAL := help

CLANG   ?= clang
GO      ?= go
BPFTOOL ?= bpftool

BIN_DIR := bin
BINARY  := $(BIN_DIR)/probe
BPF_DIR := bpf
VMLINUX := $(BPF_DIR)/vmlinux.h
CMD     := ./cmd/probe

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: vmlinux
vmlinux: ## Generate bpf/vmlinux.h from the running kernel BTF (Linux only)
	@test -f /sys/kernel/btf/vmlinux || { echo "no BTF at /sys/kernel/btf/vmlinux"; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@echo "wrote $(VMLINUX)"

.PHONY: generate
generate: ## Compile eBPF C + regenerate Go bindings (bpf2go)
	$(GO) generate ./...

.PHONY: build
build: ## Build the static probe binary
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)
	@echo "built $(BINARY) ($(VERSION))"

.PHONY: run
run: build ## Build and run (needs root to load eBPF)
	sudo $(BINARY)

.PHONY: test
test: ## Run unit tests with coverage
	$(GO) test -race -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out | tail -1

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format Go code
	gofmt -s -w .

.PHONY: tidy
tidy: ## Tidy go.mod
	$(GO) mod tidy

.PHONY: docker
docker: ## Build the container image
	docker build -t probe:$(VERSION) .

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) dist coverage.out coverage.html
