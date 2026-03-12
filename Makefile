GO ?= go
PROTOC ?= protoc

.PHONY: fmt test proto run-api

fmt:
	$(GO) fmt ./...

test:
	$(GO) test ./...

proto:
	PATH="$(shell $(GO) env GOPATH)/bin:$$PATH" $(PROTOC) --proto_path=. --go_out=. --go_opt=paths=source_relative --connect-go_out=. --connect-go_opt=paths=source_relative proto/asb/v1/broker.proto

run-api:
	$(GO) run ./cmd/asb-api
