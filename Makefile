TOOLCHAIN ?= go1.26.2
GO ?= env GOTOOLCHAIN=$(TOOLCHAIN) go

.PHONY: fmt test test-race vet lint security-scan coverage install-hooks proto proto-check migrate run-api run-worker

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

security-scan:
	$(GO) mod verify
	gosec ./cmd/... ./internal/...
	env GOTOOLCHAIN=$(TOOLCHAIN) govulncheck ./...

coverage:
	$(GO) test ./... -coverprofile=coverage.out -covermode=atomic

proto:
	bash scripts/sync-proto.sh

proto-check:
	bash scripts/sync-proto.sh --check

migrate:
	$(GO) run ./cmd/asb-migrate

run-api:
	$(GO) run ./cmd/asb-api

run-worker:
	$(GO) run ./cmd/asb-worker

install-hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed"
