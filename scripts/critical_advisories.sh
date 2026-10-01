#!/usr/bin/env bash
#
# Critical advisories with a released fix, as Trivy sees the lockfiles.
#
#   ./scripts/critical_advisories.sh list DIR
#       One line per finding: target, package, installed version, advisory,
#       fixed version. Exit 0 whatever it finds.
#
#   ./scripts/critical_advisories.sh new HEAD_DIR BASE_DIR
#       Only the findings present in HEAD_DIR and not in BASE_DIR. Exit 1 when
#       there is at least one.
#
# Why "new" exists (#430): the pull-request gate used to fail on every
# critical advisory in the tree. One published against a package already on
# main turned every open PR red at once, including PRs that touched nothing
# near it, while main itself -- the branch that ships -- was never scanned.
# A PR now fails only for an advisory it introduces; the ones already on main
# are reported by .github/workflows/main-advisories.yml, on main.
#
# A finding is keyed by (target, package, advisory), not by version: a PR
# that moves a vulnerable package to another still-vulnerable version has not
# introduced anything.

set -euo pipefail

for tool in trivy jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool is not installed" >&2; exit 2; }
done

scan() {
  local out
  out="$(mktemp)"
  trivy fs --quiet --scanners vuln --severity CRITICAL --ignore-unfixed \
    --format json --output "$out" "$1"
  jq -r '.Results[]? | .Target as $t | .Vulnerabilities[]?
         | [$t, .PkgName, .InstalledVersion, .VulnerabilityID, (.FixedVersion // "")]
         | @tsv' "$out" | sort -u
  rm -f "$out"
}

key() { cut -f1,2,4 | sort -u; }

case "${1:-}" in
  list)
    [ $# -eq 2 ] || { echo "usage: $0 list DIR" >&2; exit 2; }
    scan "$2"
    ;;
  new)
    [ $# -eq 3 ] || { echo "usage: $0 new HEAD_DIR BASE_DIR" >&2; exit 2; }
    head_list="$(scan "$2")"
    base_list="$(scan "$3")"
    new_keys="$(comm -23 <(printf '%s\n' "$head_list" | key) <(printf '%s\n' "$base_list" | key) | sed '/^$/d')"
    already="$(printf '%s\n' "$base_list" | key | sed '/^$/d' | wc -l | tr -d ' ')"
    if [ -n "$new_keys" ]; then
      echo "Critical advisories introduced by this change:"
      printf '%s\n' "$head_list" | while IFS=$'\t' read -r t p v id fix; do
        if grep -qxF "$(printf '%s\t%s\t%s' "$t" "$p" "$id")" <<< "$new_keys"; then
          printf '  %s  %s %s  %s  (fixed in %s)\n' "$t" "$p" "$v" "$id" "$fix"
        fi
      done
      exit 1
    fi
    echo "No critical advisory introduced. Already present on the base branch: ${already}."
    ;;
  *)
    echo "usage: $0 list DIR | new HEAD_DIR BASE_DIR" >&2
    exit 2
    ;;
esac
