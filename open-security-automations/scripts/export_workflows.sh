#!/bin/bash

# Wildbox Open Security Automations - workflow export
#
# Exports every workflow from the running n8n container with n8n's own CLI,
# one JSON file per workflow, into backups/workflows/<timestamp>/ (ignored by
# git: an export may hold values typed into nodes):
#
#   ./scripts/export_workflows.sh
#
# N8N_CONTAINER names the container (default: open-security-automations).
#
# This script used to read n8n's REST API with HTTP basic auth, which n8n 1.x
# answers with 401, and filed workflows into directories by guessing from
# their names.
#
# To version a workflow, copy its file into a subdirectory of workflows/ and
# run `python3 scripts/check_automation_workflows.py` from the repository
# root: CI runs the same check, and fails on a call to a route that does not
# exist.

set -euo pipefail

N8N_CONTAINER="${N8N_CONTAINER:-open-security-automations}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/backups/workflows/$(date '+%Y%m%d_%H%M%S')"
STAGING="/tmp/wildbox-export"

if ! docker inspect -f '{{.State.Running}}' "$N8N_CONTAINER" 2>/dev/null | grep -q true; then
    echo "Error: container $N8N_CONTAINER is not running." >&2
    exit 1
fi

docker exec "$N8N_CONTAINER" sh -c "rm -rf '$STAGING' && mkdir -p '$STAGING'"
docker exec "$N8N_CONTAINER" n8n export:workflow --backup --output="$STAGING/"
mkdir -p "$OUT_DIR"
docker cp "$N8N_CONTAINER:$STAGING/." "$OUT_DIR/"
docker exec "$N8N_CONTAINER" rm -rf "$STAGING"
echo "Exported $(find "$OUT_DIR" -name '*.json' | wc -l | tr -d ' ') workflow(s) to $OUT_DIR"
