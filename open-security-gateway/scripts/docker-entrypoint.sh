#!/bin/sh
# Gateway entrypoint:
#  1. Ensure a TLS cert exists (generate a self-signed one for dev if the
#     mounted /etc/ssl/wildbox is writable and empty; prod mounts real certs).
#  2. Start OpenResty with the project's nginx.conf — NOT the stock openresty
#     default, which lacks our lua_shared_dicts, rate-limit zones, `env`
#     exports and CORS maps (without them auth_handler.lua cannot run).
set -e

CRT=/etc/ssl/wildbox/wildbox.crt
KEY=/etc/ssl/wildbox/wildbox.key

if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
    if mkdir -p /etc/ssl/wildbox 2>/dev/null && [ -w /etc/ssl/wildbox ]; then
        echo "[entrypoint] No TLS cert found — generating a self-signed dev cert."
        openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT" \
            -days 365 -subj "/CN=localhost" 2>/dev/null
    else
        echo "[entrypoint] WARNING: no TLS cert and /etc/ssl/wildbox is read-only;" \
             "mount real certs at $CRT / $KEY."
    fi
fi

exec /usr/local/openresty/bin/openresty -c /etc/nginx/nginx.conf -g "daemon off;"
