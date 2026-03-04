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
  local method="${3:-GET}"
  local body="${4:-}"
  local code
  if [[ -n "$body" ]]; then
    code=$(curl -sS -o /dev/null -w "%{http_code}" -X "$method" -H "Content-Type: application/json" --data "$body" "$BASE_URL$path")
  else
    code=$(curl -sS -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path")
  fi
  echo "$method $path => $code"
  if [[ "$code" != "$expected" ]]; then
    echo "Smoke check failed for $method $path (expected $expected, got $code)"
    exit 1
  fi
}

# Existing routes should reject malformed requests with 400 (request validation).
check "/estimate/storage" 400 GET
check "/estimate/storage" 400 POST '{}'

echo "Smoke checks passed."
