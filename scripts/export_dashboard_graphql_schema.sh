#!/usr/bin/env bash
# Regenerate services/dashboard_graphql/schema.graphql from the Strawberry schema.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/services"
source "$ROOT/.venv/bin/activate" 2>/dev/null || true
strawberry export-schema dashboard_graphql.schema:schema > "$ROOT/services/dashboard_graphql/schema.graphql"
