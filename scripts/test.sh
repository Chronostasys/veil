#!/usr/bin/env bash
# Run the whole verification suite the same way CI would.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.27.3}"

cd "$ROOT/core"
echo "== gofmt =="
out=$(gofmt -l . || true)
if [[ -n "$out" ]]; then echo "$out"; exit 1; fi

echo "== go vet =="
go vet ./...

echo "== tests =="
go test ./... -count=1

echo "== race (core packages) =="
go test ./internal/supervisor/... ./internal/inbound/... ./internal/dns/... ./internal/rules/... ./internal/share/... ./internal/netstack/... -race -count=1

echo "== cross compile (HarmonyOS arm64) =="
"$ROOT/scripts/build-core.sh" >/dev/null
echo "ok"
