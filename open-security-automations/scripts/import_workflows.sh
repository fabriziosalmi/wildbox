#!/bin/bash

# Wildbox Open Security Automations - workflow import
#
# Imports the workflow definitions under ../workflows (every subdirectory)
# into the running n8n container with n8n's own CLI:
#
#   ./scripts/import_workflows.sh                    # every workflow
#   ./scripts/import_workflows.sh path/to/flow.json  # one workflow
#
# N8N_CONTAINER names the container (default: open-security-automations, the
# name docker-compose.yml at the repository root gives it).
#
# This script used to POST to n8n's REST API with HTTP basic auth. n8n 1.x
# ignores N8N_BASIC_AUTH_* and its public API answers 401 without an
# X-N8N-API-KEY header, so every import failed; it also imported only four
# hard-coded category directories, which did not include reporting/.
#
# Each workflow carries a fixed "id", so importing it again updates it in
# place instead of adding a copy. Imported workflows are inactive: attach the
# credentials the workflow's README section names, then activate it in n8n.

set -euo pipefail

N8N_CONTAINER="${N8N_CONTAINER:-open-security-automations}"
WORKFLOWS_DIR="$(cd "$(dirname "$0")/../workflows" && pwd)"
STAGING="/tmp/wildbox-workflows"

if ! docker inspect -f '{{.State.Running}}' "$N8N_CONTAINER" 2>/dev/null | grep -q true; then
    echo "Error: container $N8N_CONTAINER is not running." >&2
    echo "Start it with: docker compose --profile automations up -d automations" >&2
    exit 1
fi

if [ $# -eq 1 ]; then
    files=("$1")
else
    files=()
    while IFS= read -r -d '' file; do
        files+=("$file")
    done < <(find "$WORKFLOWS_DIR" -name '*.json' -type f -print0 | sort -z)
fi

if [ ${#files[@]} -eq 0 ]; then
    echo "Error: no workflow JSON under $WORKFLOWS_DIR" >&2
    exit 1
fi

docker exec "$N8N_CONTAINER" sh -c "rm -rf '$STAGING' && mkdir -p '$STAGING'"
for file in "${files[@]}"; do
    if ! jq -e '.id and .name and .nodes' "$file" > /dev/null; then
        echo "Error: $file is not a workflow with an id, a name and nodes" >&2
        exit 1
    fi
    echo "Staging $(jq -r .name "$file") ($file)"
    # Streamed through stdin so the copy belongs to the container's user.
    docker exec -i "$N8N_CONTAINER" sh -c "cat > '$STAGING/$(basename "$file")'" < "$file"
done

docker exec "$N8N_CONTAINER" n8n import:workflow --separate --input="$STAGING"
docker exec "$N8N_CONTAINER" rm -rf "$STAGING"
echo "Imported ${#files[@]} workflow(s). They are inactive until activated in n8n."
