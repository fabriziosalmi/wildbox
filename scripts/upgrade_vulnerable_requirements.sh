#!/usr/bin/env bash
#
# Move every package with a known advisory to the newest version its
# requirements.in allows, and touch nothing else.
#
# This replaces Dependabot for pip (#420). Dependabot regenerates a compiled
# requirements file with pip-compile, run from the service directory, with no
# --python-version or --python-platform: its lock is never the one
# compile_requirements.sh produces, so every pip PR it opened failed the
# Dependency Integrity gate and none could be merged.
#
# Here the lock is written by the same uv invocation compile_requirements.sh
# uses, with --upgrade-package for the vulnerable names only, so the result
# passes `compile_requirements.sh --check` by construction.
#
# Advisories whose fix is outside the range requirements.in allows are not
# forced: widening a constraint is a decision, not a lock refresh. They are
# listed in the summary instead.
#
# Usage:
#   ./scripts/upgrade_vulnerable_requirements.sh                 # all services
#   ./scripts/upgrade_vulnerable_requirements.sh identity tools  # some
#   SUMMARY_FILE=out.md ./scripts/upgrade_vulnerable_requirements.sh
#
# Exit status: 0 whether or not anything moved; non-zero only on a tool error.

set -euo pipefail

cd "$(dirname "$0")/.."

SERVICES=(agents cspm data guardian identity responder sensor tools ci-tools)
# Must match compile_requirements.sh, lock_dir included: `ci-tools` is the
# lock of the tools the workflows install, in tests/ci-tools.
lock_dir() {
  case "$1" in
    ci-tools) echo "tests/ci-tools" ;;
    *) echo "open-security-$1" ;;
  esac
}
PYTHON_VERSION="3.11"
PYTHON_PLATFORM="linux"
SUMMARY_FILE="${SUMMARY_FILE:-/dev/stdout}"

if [ $# -gt 0 ]; then
  SERVICES=("$@")
fi

for tool in uv jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool is not installed" >&2; exit 1; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# pip-audit exits 1 when it finds something; only a missing report is an error.
audit() {
  uvx --quiet pip-audit==2.10.1 -r "$1" --no-deps --disable-pip -s osv \
    --format json -o "$2" >/dev/null 2>&1 || true
  [ -s "$2" ] || { echo "ERROR: pip-audit produced no report for $1" >&2; exit 1; }
}

vulnerable() {
  jq -r '.dependencies[] | select(.vulns | length > 0)
         | "\(.name) \(.version) \([.vulns[].id] | unique | join(","))"' "$1"
}

upgraded=""
residual=""

for svc in "${SERVICES[@]}"; do
  dir="$(lock_dir "$svc")"
  [ -f "${dir}/requirements.in" ] || { echo "skip ${svc}: no requirements.in" >&2; continue; }

  audit "${dir}/requirements.txt" "$work/${svc}-before.json"
  names="$(vulnerable "$work/${svc}-before.json" | cut -d' ' -f1)"
  if [ -z "$names" ]; then
    echo "clean: ${svc}" >&2
    continue
  fi

  cp "${dir}/requirements.txt" "$work/${svc}-old.txt"
  args=()
  while read -r name; do
    args+=("--upgrade-package=${name}")
  done <<< "$names"

  echo "upgrading ${svc}: $(echo "$names" | tr '\n' ' ')" >&2
  uv pip compile --quiet --generate-hashes --python-version "$PYTHON_VERSION" \
    --python-platform "$PYTHON_PLATFORM" "${args[@]}" \
    "${dir}/requirements.in" -o "${dir}/requirements.txt"

  # Old and new version of every pin that moved, read from the locks themselves.
  while read -r name; do
    old="$(grep -iE "^${name}(\[[^]]*\])?==" "$work/${svc}-old.txt" | head -1 | sed -E 's/.*==([^ ]+).*/\1/')"
    new="$(grep -iE "^${name}(\[[^]]*\])?==" "${dir}/requirements.txt" | head -1 | sed -E 's/.*==([^ ]+).*/\1/')"
    if [ -n "$old" ] && [ "$old" != "$new" ]; then
      upgraded+="| ${svc} | \`${name}\` | ${old} | ${new} |"$'\n'
    fi
  done <<< "$names"

  audit "${dir}/requirements.txt" "$work/${svc}-after.json"
  while read -r name version ids; do
    [ -n "$name" ] || continue
    pin="$(grep -iE "^${name}[^a-z0-9_.-]" "${dir}/requirements.in" | head -1 || true)"
    residual+="| ${svc} | \`${name}\` ${version} | ${ids} | \`${pin:-transitive}\` |"$'\n'
  done < <(vulnerable "$work/${svc}-after.json")
done

{
  echo "## Upgraded"
  echo
  if [ -n "$upgraded" ]; then
    echo "| Service | Package | From | To |"
    echo "|---|---|---|---|"
    printf '%s' "$upgraded"
  else
    echo "Nothing could be moved within the ranges \`requirements.in\` allows."
  fi
  echo
  echo "## Still vulnerable: the fix is outside the allowed range"
  echo
  if [ -n "$residual" ]; then
    echo "These need a constraint in \`requirements.in\` widened by hand, then"
    echo "\`./scripts/compile_requirements.sh <service>\`."
    echo
    echo "| Service | Package | Advisories | Constraint in requirements.in |"
    echo "|---|---|---|---|"
    printf '%s' "$residual"
  else
    echo "None."
  fi
} > "$SUMMARY_FILE"
