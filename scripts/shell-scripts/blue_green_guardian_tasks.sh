#!/bin/bash
#
# Move guardian's background tasks to one color (#550)
#
# guardian runs its Celery tasks in guardian-worker-<color> and sends its
# periodic tasks from guardian-beat, of which there is exactly one for both
# colors (docker-compose.blue-green.yml explains why). When the traffic
# moves to a color, this moves the tasks with it, in an order that never
# leaves the queues unconsumed and never runs two beats:
#
#   1. start the new color's worker (its queues are then read by both);
#   2. recreate guardian-beat on the new color's image: compose stops the
#      old beat container before it starts the new one (fixed
#      container_name), so there is at most one beat at every moment;
#   3. stop the old color's worker: a warm shutdown, which finishes the
#      tasks it is running (stop_grace_period) before exiting.
#
# Between 1 and 3 tasks from either color may run on either color's code,
# as requests do during any blue/green switch on a shared database: task
# arguments and migrations must stay compatible across one release.
#
# Usage:
#   ./blue_green_guardian_tasks.sh <blue|green>
#
# Called by blue_green_deploy.sh and blue_green_rollback.sh after the
# traffic switch. COMPOSE (default: "docker compose -f
# docker-compose.blue-green.yml") selects the stack.

set -euo pipefail

NEW=${1:-}
case "$NEW" in
  blue) OLD=green ;;
  green) OLD=blue ;;
  *)
    echo "Usage: $0 <blue|green>" >&2
    exit 2
    ;;
esac

COMPOSE=${COMPOSE:-docker compose -f docker-compose.blue-green.yml}
# Workers of the new color; guardian-worker-green is at 0 replicas until now.
WORKERS=${GUARDIAN_WORKERS:-1}

echo "guardian tasks -> $NEW"

# --no-deps throughout: `up` of a service with its dependencies would also
# reconcile them to this file's replica counts (guardian-green: 0).
echo "1/3 starting guardian-worker-$NEW"
$COMPOSE up -d --no-deps --wait --scale "guardian-worker-$NEW=$WORKERS" "guardian-worker-$NEW"

echo "2/3 moving guardian-beat to $NEW"
GUARDIAN_ACTIVE_COLOR=$NEW $COMPOSE up -d --no-deps --wait guardian-beat

beats=$($COMPOSE ps -q guardian-beat | wc -l | tr -d ' ')
if [ "$beats" -ne 1 ]; then
  echo "expected one guardian-beat container, found $beats" >&2
  exit 1
fi

echo "3/3 stopping guardian-worker-$OLD (finishes its running tasks first)"
$COMPOSE stop "guardian-worker-$OLD"

echo "guardian tasks now run on $NEW."
if [ "$NEW" != blue ]; then
  # The compose file's default is blue; see its guardian-beat comment.
  echo "Pass GUARDIAN_ACTIVE_COLOR=$NEW to any later 'docker compose up' that"
  echo "includes guardian-beat, or beat goes back to blue's image."
fi
