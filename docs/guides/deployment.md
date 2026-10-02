# Deployment Guide

How to run Wildbox on a server you control. Wildbox is in an early evaluation
phase: it is suitable for testing, staging and community deployments, and
real-world deployment feedback is welcome in
[Discussions](https://github.com/fabriziosalmi/wildbox/discussions) and
[Issues](https://github.com/fabriziosalmi/wildbox/issues).

This guide builds on the [Quick Start](quickstart.md); read it first. Ports
and service names are listed once, in [Service ports](ports.md).

---

## 1. Server Requirements

- Linux with Docker Engine 20.10+ and the Compose plugin 2.24.4 or later
  (`docker-compose.prod.yml` uses the `!override` tag, which older versions
  reject)
- 8 GB RAM minimum (16 GB recommended), 50 GB SSD
- A DNS name for the server and a TLS certificate for it
- Somewhere off the server to keep backups

Open only what the gateway needs. Every other service is bound to `127.0.0.1`
by `docker-compose.yml`, and PostgreSQL and Redis publish nothing:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp     # SSH; restrict to your addresses if you can
sudo ufw allow 443/tcp    # HTTPS through the gateway
sudo ufw allow 80/tcp     # optional: /health and the redirect to HTTPS
sudo ufw enable
```

Docker publishes ports through its own iptables rules, which can bypass ufw.
That is why the backend ports are bound to `127.0.0.1` in the Compose file;
do not change those bindings.

---

## 2. Get the Code and Generate Secrets

```bash
git clone https://github.com/fabriziosalmi/wildbox.git
cd wildbox
make generate-secrets
make validate-secrets
```

Then edit `.env` and set the values that describe your deployment rather
than secrets:

- `INITIAL_ADMIN_EMAIL`: the first administrator's login
- `CORS_ORIGINS`: the HTTPS origins that may call the API, for example
  `https://wildbox.example.com` (here and below, replace `wildbox.example.com`,
  a name reserved for documentation, with your host name). identity does not
  read it: the browser reaches identity through the gateway, on the same
  origin as the dashboard
- `ENVIRONMENT=production` (the template default)

Do not generate secrets by hand or copy them from documentation. The
[Credentials guide](credentials.md) explains every generated value and how to
rotate it.

---

## 3. TLS Certificate

The gateway reads its certificate from `open-security-gateway/ssl/`, mounted
at `/etc/ssl/wildbox/`:

- `open-security-gateway/ssl/wildbox.crt`: certificate, with the full chain
- `open-security-gateway/ssl/wildbox.key`: private key

If neither file exists when the gateway starts, it generates a self-signed
development certificate there. For a real deployment, put your certificate in
place before the first start, for example from Let's Encrypt:

```bash
sudo certbot certonly --standalone -d wildbox.example.com
sudo install -m 0644 /etc/letsencrypt/live/wildbox.example.com/fullchain.pem \
  open-security-gateway/ssl/wildbox.crt
sudo install -m 0600 /etc/letsencrypt/live/wildbox.example.com/privkey.pem \
  open-security-gateway/ssl/wildbox.key
```

TLS terminates at the gateway; no other proxy is needed in front of it. The
`haproxy/` directory in the repository belongs to the blue/green experiment in
`docker-compose.blue-green.yml` and is not used by `docker-compose.yml` or
`docker-compose.prod.yml`.

`certbot --standalone` needs port 80 free, so run it before the stack starts or
stop the gateway while it renews. After replacing the files, restart the
gateway: `docker compose restart gateway`.

---

## 4. Start the Stack

`make start-prod` composes `docker-compose.yml` with `docker-compose.prod.yml`
(`restart: always`, log rotation, tuned connection limits, and network
segmentation: only the gateway and the dashboard share the public-facing
network, and PostgreSQL and Redis sit on an internal network reachable only
by the services that use them; the map is at the top of
`docker-compose.prod.yml`). To check it on a host:
`python3 scripts/check_network_segmentation.py config`, and with the stack
running, `COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml python3
scripts/check_network_segmentation.py runtime`.

```bash
make start-prod
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
```

Databases are created by `scripts/init-databases.sql` on PostgreSQL's first
start, and the identity service creates the first administrator from
`INITIAL_ADMIN_EMAIL` and `INITIAL_ADMIN_PASSWORD`. Nothing needs to be created
by hand.

Optional services:

```bash
docker compose --profile automations up -d   # n8n workflows
docker compose --profile monitoring up -d    # Prometheus with monitoring/alert_rules.yml
docker compose --profile backup up -d        # scheduled PostgreSQL backups
```

---

## 5. Verify

```bash
curl -s http://localhost/health                      # gateway
curl -sI https://wildbox.example.com/ | head -20     # TLS and security headers
```

Then log in through the gateway with the sequence in the
[Quick Start](quickstart.md#5-log-in-and-call-the-api), using your host name
and dropping `--cacert` once the certificate is publicly trusted. The health
loop on the [Service ports](ports.md#checking-the-stack) page checks every
backend from the server itself.

---

## 6. Backups and Restore

`scripts/backup_postgres.sh` writes `pg_dump` archives of every database,
with optional GPG encryption (`GPG_RECIPIENT`) and S3 upload (`--upload-s3`,
`S3_BUCKET`). `scripts/restore_postgres.sh` restores them, and
`scripts/verify_restore.sh` is a drill: back up, restore into scratch
databases, check the data, clean up.

The `backup` Compose profile runs the backup script in a container on the
Compose network every `BACKUP_INTERVAL_SECONDS` (one day by default) and keeps
`BACKUP_RETENTION` days of archives in the `wildbox_backups` volume:

```bash
docker compose --profile backup up -d backup
docker compose logs backup
```

`make backup` and `make restore-drill` run the same scripts from the host.
They connect to `POSTGRES_HOST` (default `wildbox-postgres`), which the
default Compose file does not publish to the host, so run them from a machine
or container that can reach the database.

Copy the archives off the server: a backup on the same disk is not a backup.
Run the restore drill on a schedule; a restore that has never been tested is
not one either.

---

## 7. Monitoring

The `monitoring` profile starts Prometheus on `127.0.0.1:9090` with the
scrape configuration in `monitoring/prometheus.yml` and the alert rules in
`monitoring/alert_rules.yml`. There is no Grafana in `docker-compose.yml`;
connect your own if you want dashboards.

Container logs are rotated by the production overlay; read them with
`docker compose logs <service>`.

---

## 8. Updating

Read the notes for your target version in
[UPGRADING.md](https://github.com/fabriziosalmi/wildbox/blob/main/UPGRADING.md)
before pulling; they list what an existing deployment has to do.

```bash
git pull
make validate-secrets       # new releases can add required secrets
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
make start-prod
```

The images are built from the repository, and `make start-prod` does not
rebuild an image that already exists: build first, or the services keep
running the previous release.

---

## Troubleshooting

- **A container keeps restarting**: `docker compose logs <service>`; a missing
  secret is reported by name.
- **Clients get certificate errors**: check that `wildbox.crt` contains the
  full chain and matches your host name.
- **Requests on port 80 return 301**: expected; only `/health` is served over
  HTTP.
- **PostgreSQL**:
  `docker compose exec postgres psql -U postgres -c 'SELECT 1'`.

## Support

- [Security policy](../security/policy.md) and [Security status](../security/status.md)
- [GitHub Issues](https://github.com/fabriziosalmi/wildbox/issues)
- Security reports: see [SECURITY.md](https://github.com/fabriziosalmi/wildbox/blob/main/SECURITY.md)
