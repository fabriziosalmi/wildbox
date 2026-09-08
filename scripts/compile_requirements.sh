#!/usr/bin/env bash
#
# Compile every service's requirements.in into a hash-pinned requirements.txt.
#
# Seven of the eight Python services used to ship only their direct
# dependencies, pinned with == but with the whole transitive tree resolved fresh
# at each image build. Two builds of the same commit therefore installed
# different code, nothing verified the artefacts that were downloaded, and the
# resolver was free to choose versions no one had reviewed (WILDBO-DEP-04/DEP-05).
#
# Usage:
#   ./scripts/compile_requirements.sh            # compile all services
#   ./scripts/compile_requirements.sh data tools # compile specific services
#   ./scripts/compile_requirements.sh --check    # fail if any lock is stale (CI)
#   ./scripts/compile_requirements.sh --upgrade  # ignore the current lock's pins
#
# Without --upgrade, uv treats the existing requirements.txt as preferences and
# keeps a version that still satisfies requirements.in. That is what you want
# day to day (a one-line change should not move the whole tree), but it also
# means widening a range in requirements.in has no visible effect: relaxing
# pydantic in cspm and data left FastAPI pinned at the 0.125 the old lock
# already held. Use --upgrade after loosening a constraint on purpose.

set -euo pipefail

cd "$(dirname "$0")/.."

SERVICES=(agents cspm data guardian identity responder sensor tools)
PYTHON_VERSION="3.11"
# Resolve for the platform the images actually run on, not the developer's.
# Compiled on macOS without this, the sensor lock picked up pyobjc-core, whose
# build refuses to run anywhere else ("PyObjC requires macOS to build") -- so
# the lock installed cleanly for whoever generated it and broke every Linux
# image build. It also means the same requirements.in produces the same lock
# from a laptop and from CI.
PYTHON_PLATFORM="linux"
CHECK_ONLY=false
UPGRADE=""

args=()
for a in "$@"; do
  case "$a" in
    --check) CHECK_ONLY=true ;;
    --upgrade) UPGRADE="--upgrade" ;;
    *) args+=("$a") ;;
  esac
done
if [ ${#args[@]} -gt 0 ]; then
  SERVICES=("${args[@]}")
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: uv is not installed. See https://docs.astral.sh/uv/"
  exit 1
fi

status=0
for svc in "${SERVICES[@]}"; do
  dir="open-security-${svc}"
  [ -f "${dir}/requirements.in" ] || { echo "skip ${svc}: no requirements.in"; continue; }

  if [ "$CHECK_ONLY" = true ]; then
    tmp="$(mktemp)"
    uv pip compile --quiet --generate-hashes --python-version "$PYTHON_VERSION" \
      --python-platform "$PYTHON_PLATFORM" "${dir}/requirements.in" -o "$tmp"
    # Compare ignoring the header comment, which records the invoking command.
    if ! diff -q <(grep -v '^#' "$tmp") <(grep -v '^#' "${dir}/requirements.txt") >/dev/null; then
      echo "STALE: ${dir}/requirements.txt does not match requirements.in"
      echo "       run ./scripts/compile_requirements.sh ${svc}"
      status=1
    else
      echo "ok:    ${svc}"
    fi
    rm -f "$tmp"
  else
    echo "compiling ${svc}..."
    uv pip compile --quiet --generate-hashes --python-version "$PYTHON_VERSION" \
      --python-platform "$PYTHON_PLATFORM" $UPGRADE \
      "${dir}/requirements.in" -o "${dir}/requirements.txt"
  fi
done

exit "$status"
