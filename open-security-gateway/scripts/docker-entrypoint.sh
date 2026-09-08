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
        # With subjectAltName. A certificate carrying only a CN is rejected
        # outright by every current TLS client -- OpenSSL 3 and Python 3.7+
        # stopped falling back to the CN years ago -- so the previous
        # "/CN=localhost" cert could not be verified by anything, no matter
        # whose trust store it was placed in. Anything talking to the gateway
        # was therefore forced to disable verification entirely.
        #
        # The names are the ones the gateway answers to: the server_name in
        # conf.d/wildbox_gateway.conf, the compose service name and its
        # container_name (used by other containers), and loopback.
        openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT" \
            -days 365 -subj "/CN=api.wildbox.local" \
            -addext "subjectAltName=DNS:api.wildbox.local,DNS:wildbox.local,DNS:*.wildbox.local,DNS:localhost,DNS:gateway,DNS:open-security-gateway,IP:127.0.0.1" \
            2>/dev/null
    else
        echo "[entrypoint] WARNING: no TLS cert and /etc/ssl/wildbox is read-only;" \
             "mount real certs at $CRT / $KEY."
    fi
fi

exec /usr/local/openresty/bin/openresty -c /etc/nginx/nginx.conf -g "daemon off;"
