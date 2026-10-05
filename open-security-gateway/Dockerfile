# Base image pinned by digest: a floating tag is republished upstream, so the
# same commit built a month apart produced a different interpreter patch level,
# a different OpenSSL and a different set of OS CVEs, with nothing recording
# which one shipped (WILDBO-BLD-01). Dependabot's docker ecosystem proposes
# digest bumps as reviewable PRs.
FROM openresty/openresty:alpine@sha256:b3a6f1f432eabdbda4adcb6ec3e6461e621782eaa82dbe67154ddd1afd109569

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
# The three files are checked against SHA-256 values recorded here: a git tag
# can be moved, and the gateway runs this code on every authenticated request
# (#657). The values are those of the files at tag v0.17.2 (commit 18331032).
RUN cd /usr/local/openresty/lualib/resty \
    && wget -O http.lua https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/http.lua \
    && wget -O http_headers.lua https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/http_headers.lua \
    && wget -O http_connect.lua https://raw.githubusercontent.com/ledgetech/lua-resty-http/v0.17.2/lib/resty/http_connect.lua \
    && printf '%s  %s\n' \
        3587e013ada745c4976280037c5ce4d41a7e463b720bb5e49683ac732caef1cd http.lua \
        4dc87bc7c47be6e26e6ab4905945a146649b2b64c8da894d594dec50f6d6dc1a http_headers.lua \
        3b093b4be129f0d3a8ee723dc4b6c1d4d18da466d556ce1b9e3ee314a0b98b7f http_connect.lua \
        | sha256sum -c -

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
