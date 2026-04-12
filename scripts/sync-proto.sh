#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PATH="$(go env GOPATH)/bin:${PATH}"

buf lint
buf generate

if [[ "${1:-}" == "--check" ]]; then
  git diff --exit-code -- proto/asb/v1/broker.pb.go proto/asb/v1/asbv1connect/broker.connect.go
fi
