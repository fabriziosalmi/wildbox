#!/bin/sh
# Apply Django migrations before serving. Guardian has no migrate-on-boot, so a
# fresh database (e.g. first `docker compose up`) would leave its tables absent
# and every API request would 500 with 'relation "auth_user" does not exist'.
# migrate is idempotent — it only applies what's pending.
set -e

echo "[entrypoint] Applying database migrations..."
python manage.py migrate --no-input

exec "$@"
