GO ?= go

.PHONY: fmt test vet proto proto-check migrate run-api run-worker

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

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
