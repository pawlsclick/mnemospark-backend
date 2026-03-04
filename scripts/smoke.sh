#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-}"
if [[ -z "$BASE_URL" ]]; then
  echo "Usage: $0 <base-url>"
  exit 2
fi

check() {
  local path="$1"
  local expected="${2:-200}"
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" "$BASE_URL$path")
  echo "$path => $code"
  if [[ "$code" != "$expected" ]]; then
    echo "Smoke check failed for $path (expected $expected, got $code)"
    exit 1
  fi
}

# Update paths to match your API surface
check "/health" 200
check "/" 200

echo "Smoke checks passed."
