#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-}"
if [[ -z "$BASE_URL" ]]; then
  echo "Usage: $0 <base-url>"
  exit 2
fi

check_any() {
  local path="$1"
  local method="$2"
  shift 2
  local expected_codes=("$@")
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path")
  echo "$method $path => $code"
  for expected in "${expected_codes[@]}"; do
    if [[ "$code" == "$expected" ]]; then
      return 0
    fi
  done
  echo "Smoke check failed for $method $path (expected one of: ${expected_codes[*]}, got $code)"
  exit 1
}

# Decommissioned estimate routes should no longer exist.
check_any "/estimate/storage" GET 403 404
check_any "/estimate/storage" POST 403 404
check_any "/estimate/transfer" GET 403 404
check_any "/estimate/transfer" POST 403 404

echo "Smoke checks passed."
