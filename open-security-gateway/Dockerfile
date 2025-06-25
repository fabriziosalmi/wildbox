FROM openresty/openresty:alpine

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

# Install lua-resty-http directly without luarocks due to manifest issues
RUN cd /usr/local/openresty/lualib/resty \
    && wget -O http.lua https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http.lua \
    && wget -O http_headers.lua https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http_headers.lua

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

# Start OpenResty
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
