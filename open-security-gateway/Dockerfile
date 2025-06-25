FROM openresty/openresty:alpine

# Install dependencies
RUN apk add --no-cache \
    curl \
    openssl \
    ca-certificates \
    gettext

# Create directories
RUN mkdir -p /etc/nginx/lua \
    && mkdir -p /var/log/nginx \
    && mkdir -p /var/cache/nginx \
    && mkdir -p /etc/ssl/wildbox

# Install lua-resty-http for internal service communication
RUN /usr/local/openresty/luajit/bin/luarocks install lua-resty-http

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
