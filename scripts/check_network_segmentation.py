#!/usr/bin/env python3
"""Verify the production network segmentation (#494).

Two checks, both against the production configuration
(docker-compose.yml + docker-compose.prod.yml):

  config   Render it with `docker compose config` and compare every service's
           networks, the gateway-facing aliases and the network properties
           with EXPECTED_NETWORKS below. Needs no running stack.

  runtime  Against a running production stack, open TCP connections from
           inside the containers: each attachment in the map must carry the
           connection it exists for, and the paths segmentation is meant to
           remove (dashboard -> data layer and backends, gateway -> data
           layer, the data layer -> internet) must fail.

The rendered map is the authority for what segmentation *is*; the runtime
probes prove Docker enforces it. The issue this guards against was invisible
for exactly that reason -- the overlay looked segmented, and only the
rendered configuration showed every service still on the flat network.

Usage:
  scripts/check_network_segmentation.py config [--env-file FILE]
  scripts/check_network_segmentation.py runtime

`runtime` runs `docker compose exec` with no -f, so set COMPOSE_FILE to the
files the stack was started with.
"""

import argparse
import json
import subprocess
import sys

COMPOSE_FILES = ["docker-compose.yml", "docker-compose.prod.yml"]
PROFILES = ["automations", "backup", "monitoring"]

# service -> the exact set of networks it must be attached to in production.
EXPECTED_NETWORKS = {
    "gateway": {"frontend", "backend"},
    "dashboard": {"frontend"},
    "identity": {"backend", "data"},
    "api": {"backend", "data"},
    "data": {"backend", "data"},
    "cspm": {"backend", "data"},
    "guardian": {"backend", "data"},
    "responder": {"backend", "data"},
    "agents": {"backend", "data"},
    "sensor": {"backend"},
    "automations": {"backend"},
    "prometheus": {"backend"},
    "tools-worker": {"data", "egress"},
    "tools-flower": {"data", "egress"},
    "data-scheduler": {"data", "egress"},
    "backup": {"data", "egress"},
    "postgres": {"data"},
    "wildbox-redis": {"data"},
}

# (service, network, alias): hostnames the gateway's upstreams resolve that
# exist only as aliases, not as container names.
EXPECTED_ALIASES = [
    ("api", "backend", "open-security-tools"),
    ("data", "backend", "open-security-data"),
    ("cspm", "backend", "open-security-cspm"),
    ("dashboard", "frontend", "dashboard"),
]

# (from service, host, port, why)
MUST_CONNECT = [
    ("dashboard", "open-security-gateway", 8080, "SSR via INTERNAL_GATEWAY_URL"),
    ("gateway", "open-security-identity", 8001, "identity_service upstream + auth"),
    ("gateway", "open-security-tools", 8000, "api_service upstream"),
    ("gateway", "open-security-data", 8002, "data_service upstream"),
    ("gateway", "open-security-cspm", 8019, "cspm_service upstream"),
    ("gateway", "open-security-guardian", 8013, "guardian_service upstream"),
    ("gateway", "open-security-responder", 8018, "responder_service upstream"),
    ("gateway", "open-security-agents", 8006, "agents_service upstream"),
    ("gateway", "open-security-dashboard", 3000, "dashboard_service upstream"),
    ("gateway", "dashboard", 3000, "dashboard_service backup upstream"),
    ("identity", "open-security-gateway", 8081, "auth-cache purge listener"),
    ("identity", "wildbox-postgres", 5432, "DATABASE_URL"),
    ("identity", "wildbox-redis", 6379, "REDIS_URL"),
    ("api", "wildbox-redis", 6379, "REDIS_URL"),
    ("tools-worker", "wildbox-redis", 6379, "REDIS_URL (Celery broker)"),
    ("tools-flower", "wildbox-redis", 6379, "REDIS_URL (Celery broker)"),
    ("data", "wildbox-postgres", 5432, "DATABASE_URL"),
    ("data-scheduler", "wildbox-postgres", 5432, "DATABASE_URL"),
    ("guardian", "wildbox-postgres", 5432, "DATABASE_URL"),
    ("guardian", "wildbox-redis", 6379, "REDIS_URL / CELERY_BROKER_URL"),
    ("responder", "wildbox-postgres", 5432, "DATABASE_URL"),
    ("responder", "wildbox-redis", 6379, "REDIS_URL"),
    ("cspm", "wildbox-redis", 6379, "REDIS_URL / CELERY_BROKER_URL"),
    ("agents", "wildbox-redis", 6379, "REDIS_URL / CELERY_BROKER_URL"),
    ("agents", "api", 8000, "WILDBOX_API_URL"),
    ("sensor", "open-security-data", 8002, "ingest endpoint"),
    ("api", "github.com", 443, "outbound internet via backend"),
    ("agents", "api.anthropic.com", 443, "outbound internet via backend"),
    ("tools-worker", "github.com", 443, "outbound internet via egress"),
    ("data-scheduler", "github.com", 443, "outbound internet via egress"),
]

MUST_NOT_CONNECT = [
    ("dashboard", "wildbox-postgres", 5432, "frontend has no data access"),
    ("dashboard", "wildbox-redis", 6379, "frontend has no data access"),
    ("dashboard", "open-security-identity", 8001, "dashboard goes through the gateway"),
    ("dashboard", "open-security-tools", 8000, "dashboard goes through the gateway"),
    ("dashboard", "open-security-data", 8002, "dashboard goes through the gateway"),
    ("dashboard", "open-security-agents", 8006, "dashboard goes through the gateway"),
    ("gateway", "wildbox-postgres", 5432, "gateway is not on data"),
    ("gateway", "wildbox-redis", 6379, "gateway is not on data"),
    ("sensor", "wildbox-postgres", 5432, "sensor is not on data"),
    ("sensor", "wildbox-redis", 6379, "sensor is not on data"),
    (
        "gateway",
        "open-security-tools-flower",
        5555,
        "flower is on data and egress only",
    ),
    ("postgres", "github.com", 443, "data is internal: no route out"),
]

# Runs inside the container with "$0"=host "$1"=port. Exit 0: TCP connection
# established; 2: name does not resolve; 3: resolved, connection failed.
# Uses whichever of python3 / node / curl / bash the image has.
PROBE = r"""
h="$0"; p="$1"
if command -v python3 >/dev/null 2>&1; then
  exec python3 -c '
import socket, sys
h, p = sys.argv[1], int(sys.argv[2])
try:
    socket.getaddrinfo(h, p)
except socket.gaierror:
    sys.exit(2)
try:
    socket.create_connection((h, p), timeout=4).close()
except OSError:
    sys.exit(3)
' "$h" "$p"
elif command -v node >/dev/null 2>&1; then
  exec node -e '
const [h, p] = process.argv.slice(1);
require("dns").lookup(h, (e) => {
  if (e) process.exit(2);
  const s = require("net").connect({ host: h, port: +p });
  s.setTimeout(4000, () => process.exit(3));
  s.on("connect", () => process.exit(0));
  s.on("error", () => process.exit(3));
});
' "$h" "$p"
else
  t=$(curl -s -o /dev/null -w "%{time_connect}" --connect-timeout 4 -m 6 "http://$h:$p/")
  rc=$?
  [ "$rc" -eq 6 ] && exit 2
  case "$t" in ""|0|0.0*) exit 3 ;; esac
  exit 0
elif command -v bash >/dev/null 2>&1; then
  getent hosts "$h" >/dev/null || exit 2
  timeout 4 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null || exit 3
  exit 0
fi
exit 4
"""

RESULT = {0: "connected", 2: "does not resolve", 3: "connection failed"}


def compose_config(env_file):
    cmd = ["docker", "compose"]
    for f in COMPOSE_FILES:
        cmd += ["-f", f]
    if env_file:
        cmd += ["--env-file", env_file]
    for p in PROFILES:
        cmd += ["--profile", p]
    cmd += ["config", "--format", "json"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"docker compose config failed:\n{r.stderr}")
    return json.loads(r.stdout)


def check_config(env_file):
    cfg = compose_config(env_file)
    services = cfg["services"]
    failures = []

    unexpected = set(services) - set(EXPECTED_NETWORKS)
    missing = set(EXPECTED_NETWORKS) - set(services)
    if unexpected:
        failures.append(f"services with no expected network set: {sorted(unexpected)}")
    if missing:
        failures.append(f"expected services not rendered: {sorted(missing)}")

    for name in sorted(services):
        got = set((services[name].get("networks") or {}).keys())
        want = EXPECTED_NETWORKS.get(name)
        mark = "ok  " if got == want else "FAIL"
        print(f"  {mark} {name:15} {sorted(got)}")
        if want is not None and got != want:
            failures.append(f"{name}: networks {sorted(got)}, expected {sorted(want)}")

    for svc, net, alias in EXPECTED_ALIASES:
        nets = services.get(svc, {}).get("networks") or {}
        aliases = (nets.get(net) or {}).get("aliases") or []
        if alias not in aliases:
            failures.append(f"{svc}: alias {alias!r} missing on {net}")

    nets = cfg.get("networks", {})
    if not nets.get("data", {}).get("internal"):
        failures.append("network data must be internal")
    # backend is deliberately not internal; see docker-compose.prod.yml.
    for n in ("frontend", "backend", "egress"):
        if nets.get(n, {}).get("internal"):
            failures.append(f"network {n} must not be internal")
    icc = (
        nets.get("egress", {})
        .get("driver_opts", {})
        .get("com.docker.network.bridge.enable_icc")
    )
    if str(icc).lower() != "false":
        failures.append(
            "network egress must set com.docker.network.bridge.enable_icc=false"
        )
    used = {n for s in services.values() for n in (s.get("networks") or {})}
    if "wildbox" in used:
        failures.append("a service is still attached to the flat wildbox network")
    return failures


def probe(service, host, port):
    r = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            service,
            "sh",
            "-c",
            PROBE,
            host,
            str(port),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return r.returncode, (r.stderr or "").strip()


def check_runtime():
    failures = []
    for expect_ok, table in ((True, MUST_CONNECT), (False, MUST_NOT_CONNECT)):
        print("Must connect:" if expect_ok else "Must NOT connect:")
        for svc, host, port, why in table:
            rc, err = probe(svc, host, port)
            if rc not in RESULT:
                failures.append(f"{svc} -> {host}:{port}: probe error rc={rc} {err}")
                print(f"  ERR  {svc:15} -> {host}:{port}  rc={rc} {err}")
                continue
            ok = (rc == 0) == expect_ok
            print(
                f"  {'ok  ' if ok else 'FAIL'} {svc:15} -> {host}:{port:<5} "
                f"{RESULT[rc]:18} ({why})"
            )
            if not ok:
                failures.append(f"{svc} -> {host}:{port}: {RESULT[rc]} ({why})")
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["config", "runtime"])
    ap.add_argument("--env-file", help="env file for `docker compose config`")
    args = ap.parse_args()
    if args.mode == "config":
        print("Rendered production networks:")
        failures = check_config(args.env_file)
    else:
        failures = check_runtime()
    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nAll segmentation checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
