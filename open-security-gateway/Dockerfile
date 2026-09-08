# Base image pinned by digest: a floating tag is republished upstream, so the
# same commit built a month apart produced a different interpreter patch level,
# a different OpenSSL and a different set of OS CVEs, with nothing recording
# which one shipped (WILDBO-BLD-01). Dependabot's docker ecosystem proposes
# digest bumps as reviewable PRs.
FROM openresty/openresty:alpine@sha256:99b32fe3e411c98033114dd471440fb702992d0953ce8b6e6b5c016285ac2ab9

# Build metadata. Nothing used to be baked in, so an image identified by digest,
# retagged, or copied to another registry lost the link to its commit -- the tag
# was the only trace (WILDBO-BLD-03). CI passes GIT_SHA=${{ github.sha }}.
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ENV WILDBOX_GIT_SHA=$GIT_SHA \
    WILDBOX_BUILD_DATE=$BUILD_DATE
LABEL org.opencontainers.image.revision=$GIT_SHA \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.source="https://github.com/fabriziosalmi/wildbox"
# Install dependencies including build tools and luarocks
RUN apk add --no-cache \
    curl \
    openssl \
    ca-certificates \
    gettext \
    unzip \
    wget \
    make \
    gcc \
    musl-dev

# Create directories
RUN mkdir -p /etc/nginx/lua \
    && mkdir -p /var/log/nginx \
    && mkdir -p /var/cache/nginx \
    && mkdir -p /etc/ssl/wildbox

# Install lua-resty-http from official release (v0.17.2)
# Using pinned version for stability instead of master branch
RUN cd /usr/local/openresty/lualib/resty \
    && wget -O http.lua https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/http.lua \
    && wget -O http_headers.lua https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/http_headers.lua \
    && wget -O http_connect.lua https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/http_connect.lua

# Copy configuration files
COPY nginx/ /etc/nginx/
COPY scripts/ /usr/local/bin/

# Make scripts executable
RUN chmod +x /usr/local/bin/*.sh

# Create nginx user and set permissions
RUN adduser -D -s /bin/sh nginx \
    && chown -R nginx:nginx /var/log/nginx \
    && chown -R nginx:nginx /var/cache/nginx \
    && chown -R nginx:nginx /etc/nginx

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/health || exit 1

# Start OpenResty via the entrypoint, which loads /etc/nginx/nginx.conf
# (the stock openresty default config does NOT load our rate-limit zones,
# lua_shared_dicts or env exports, so auth_handler.lua would fail) and ensures
# a TLS cert exists.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
