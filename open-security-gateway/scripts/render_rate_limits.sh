#!/bin/sh
# The gateway's per-address request limits, written for nginx to include
# (#756).
#
# nginx.conf used to define the limit_req zones itself, with their rates
# written in: 100 requests a second per client address for everything, 5 for
# the login, registration and password-reset routes, 500 for the dashboard's
# static assets. An operator could not change them without editing the
# configuration, and neither could the stacks CI starts: the integration
# suite sends every request from one address, faster than a person or a
# dashboard does, and a test that had nothing to do with rate limiting got
# nginx's 429.
#
# limit_req_zone takes its rate as a literal -- no variable, nothing from the
# environment -- so the three zones are written here, when the container
# starts, into a file nginx.conf includes. The rates come from three
# settings of the container, each with the value nginx.conf had as its
# default:
#
#   GATEWAY_RATE_LIMIT_PER_SECOND         zone "global"         100
#   GATEWAY_AUTH_RATE_LIMIT_PER_SECOND    zone "auth"             5
#   GATEWAY_STATIC_RATE_LIMIT_PER_SECOND  zone "static_assets"  500
#
# A value that is not a whole number from 1 to 100000 stops the container
# here, naming the setting, before nginx is started: a limit the operator did
# not set is never served, as for RATE_LIMIT_PER_HOUR (#627). Unset means the
# default; set to nothing is refused like any other value that is not a
# number. Only digits are ever written into the file.
#
# These are operator settings. They are read once, from the container's
# environment, and nothing a client sends reaches them: the zones are keyed by
# the address of the connection ($binary_remote_addr), never by a header. The
# bursts stay in conf.d/wildbox_gateway.conf, beside the routes they belong
# to.
#
# Usage: render_rate_limits.sh [output file]
set -eu

OUTPUT="${1:-/run/wildbox-gateway/limit_req_zones.conf}"
MAX_RATE=100000

# rate <setting> <value>: the value, if it is a whole number from 1 to
# MAX_RATE written in digits alone, without a sign, a space or a leading
# zero. Anything else is refused by name.
rate() {
    valid=yes
    case "$2" in
        '' | *[!0-9]* | 0*) valid=no ;;
    esac
    # The length first: a number of many digits would overflow the shell's
    # arithmetic before it could be compared.
    if [ "$valid" = yes ] && [ "${#2}" -gt "${#MAX_RATE}" ]; then
        valid=no
    fi
    if [ "$valid" = yes ] && [ "$2" -gt "$MAX_RATE" ]; then
        valid=no
    fi
    if [ "$valid" = no ]; then
        # What was given, for the log: its first 64 characters, with anything
        # but plain letters, digits and a few signs shown as "?".
        shown=$(printf '%s' "$2" | LC_ALL=C tr -c 'A-Za-z0-9 ._,:;/+=-' '?' | cut -c1-64)
        echo "[rate-limits] $1 must be a whole number of requests per second between 1 and $MAX_RATE, got '$shown'" >&2
        return 1
    fi
    printf '%s' "$2"
}

# ${NAME-default}: the default only when the setting is not there at all.
GLOBAL=$(rate GATEWAY_RATE_LIMIT_PER_SECOND "${GATEWAY_RATE_LIMIT_PER_SECOND-100}") || exit 1
AUTH=$(rate GATEWAY_AUTH_RATE_LIMIT_PER_SECOND "${GATEWAY_AUTH_RATE_LIMIT_PER_SECOND-5}") || exit 1
STATIC=$(rate GATEWAY_STATIC_RATE_LIMIT_PER_SECOND "${GATEWAY_STATIC_RATE_LIMIT_PER_SECOND-500}") || exit 1

# Written under another name and renamed, so nginx never includes half a
# file; readable by all, writable by the user that starts the container.
mkdir -p "$(dirname "$OUTPUT")"
umask 022
cat > "$OUTPUT.tmp" <<EOF
# Written by render_rate_limits.sh when the container starts, from
# GATEWAY_RATE_LIMIT_PER_SECOND, GATEWAY_AUTH_RATE_LIMIT_PER_SECOND and
# GATEWAY_STATIC_RATE_LIMIT_PER_SECOND. Do not edit: set them and restart.
limit_req_zone \$binary_remote_addr zone=global:10m rate=${GLOBAL}r/s;
limit_req_zone \$binary_remote_addr zone=auth:10m rate=${AUTH}r/s;
limit_req_zone \$binary_remote_addr zone=static_assets:10m rate=${STATIC}r/s;
EOF
mv -f "$OUTPUT.tmp" "$OUTPUT"

echo "[rate-limits] Per-address request limits: global ${GLOBAL} r/s, auth ${AUTH} r/s, static assets ${STATIC} r/s."
