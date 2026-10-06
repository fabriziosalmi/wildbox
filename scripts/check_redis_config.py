#!/usr/bin/env python3
"""Verify that production Redis cannot silently drop state (#530).

Redis holds authoritative state: identity's token blacklist and failed-login
lockout counters, Celery and Dramatiq queues and results, CSPM scan state,
responder run state and agents task ownership. An eviction policy deletes
those under memory pressure, so a revoked token works again and a running
playbook loses its owner. docker-compose.prod.yml once replaced the base
file's noeviction with allkeys-lru, and nothing noticed.

  config   Render docker-compose.yml + docker-compose.prod.yml and assert, for
           wildbox-redis: --maxmemory-policy noeviction, a --maxmemory, AOF
           persistence, and a container memory limit of at least twice
           maxmemory. Below that the kernel OOM-kills Redis during an AOF
           rewrite before noeviction can refuse a write. Needs no stack.

  runtime  Against the running stack, read the same settings from Redis
           itself (CONFIG GET) and the limit Docker applied, and print the
           memory in use. Needs REDIS_PASSWORD in the environment or in
           --env-file; it reaches redis-cli through the environment, never
           as an argument.

Usage:
  scripts/check_redis_config.py config [--env-file FILE]
  scripts/check_redis_config.py runtime [--env-file FILE]

`runtime` runs `docker compose` with no -f, so set COMPOSE_FILE to the files
the stack was started with.
"""

import argparse
import json
import os
import re
import subprocess
import sys

COMPOSE_FILES = ["docker-compose.yml", "docker-compose.prod.yml"]
SERVICE = "wildbox-redis"
POLICY = "noeviction"
# Container memory limit / maxmemory. See the comment on the limit in
# docker-compose.yml for the measurements behind 2.
MIN_HEADROOM = 2

# Redis memory units (redis.conf): k = 1000, kb = 1024, and so on.
_UNITS = {
    "": 1,
    "b": 1,
    "k": 1000,
    "kb": 1024,
    "m": 1000**2,
    "mb": 1024**2,
    "g": 1000**3,
    "gb": 1024**3,
}


def redis_bytes(value):
    """Parse a Redis memory value ('1gb', '512mb', '1073741824') to bytes."""
    m = re.fullmatch(r"\s*(\d+)\s*([a-zA-Z]*)\s*", str(value))
    if not m or m.group(2).lower() not in _UNITS:
        raise ValueError(f"not a Redis memory value: {value!r}")
    return int(m.group(1)) * _UNITS[m.group(2).lower()]


def command_options(command):
    """redis-server argv (list or string) -> {option: value}, last one wins."""
    argv = command.split() if isinstance(command, str) else list(command)
    opts = {}
    for i, arg in enumerate(argv):
        if arg.startswith("--"):
            nxt = argv[i + 1] if i + 1 < len(argv) else ""
            opts[arg[2:].lower()] = "" if nxt.startswith("--") else nxt
    return opts


def check_service(service):
    """Failures for one rendered `docker compose config` service entry."""
    command = service.get("command")
    if not command:
        # Without a command, redis-server runs with its built-in defaults: no
        # maxmemory, no persistence.
        return ["no command: Redis would run without maxmemory or AOF"]
    limit = (
        ((service.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    ).get("memory")
    return check_settings(command_options(command), limit)


def check_settings(opts, limit):
    """Failures for redis-server options {name: value} and a limit in bytes."""
    failures = []
    policy = opts.get("maxmemory-policy")
    if policy != POLICY:
        failures.append(
            f"--maxmemory-policy is {policy!r}, must be {POLICY!r}: any eviction "
            "policy can delete the token blacklist, lockout counters and queues"
        )
    if opts.get("appendonly") != "yes":
        failures.append(
            "--appendonly yes missing: the state would not survive a restart"
        )

    maxmemory = None
    try:
        maxmemory = redis_bytes(opts["maxmemory"])
    except KeyError:
        failures.append(
            "--maxmemory missing: Redis would grow until the container is killed"
        )
    except ValueError as e:
        failures.append(f"--maxmemory: {e}")
    if maxmemory == 0:
        failures.append("--maxmemory is 0 (unlimited)")
        maxmemory = None

    if not limit:
        failures.append("no deploy.resources.limits.memory on the container")
    elif maxmemory:
        limit = int(limit)
        if limit < MIN_HEADROOM * maxmemory:
            failures.append(
                f"container memory limit {limit} bytes is below {MIN_HEADROOM}x "
                f"maxmemory ({maxmemory} bytes): an AOF rewrite can get Redis "
                "OOM-killed before noeviction refuses a write; raise "
                "REDIS_MEMORY_LIMIT or lower REDIS_MAXMEMORY"
            )
    return failures


def compose(args, env_file, env=None):
    cmd = ["docker", "compose"]
    if env_file:
        cmd += ["--env-file", env_file]
    r = subprocess.run(cmd + args, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        sys.exit(f"docker compose {args[0]} failed:\n{r.stderr}")
    return r.stdout


def check_config(env_file):
    args = []
    for f in COMPOSE_FILES:
        args += ["-f", f]
    cfg = json.loads(compose(args + ["config", "--format", "json"], env_file))
    service = cfg["services"].get(SERVICE)
    if service is None:
        return [f"{SERVICE} not rendered"]
    opts = command_options(service.get("command") or [])
    limit = ((service.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    # Never print the whole command: it carries --requirepass.
    print(f"  maxmemory-policy {opts.get('maxmemory-policy')}")
    print(f"  maxmemory        {opts.get('maxmemory')}")
    print(f"  appendonly       {opts.get('appendonly')}")
    print(f"  memory limit     {limit.get('memory')} bytes")
    return check_service(service)


def env_value(name, env_file):
    if os.environ.get(name):
        return os.environ[name]
    value = None
    if env_file and os.path.exists(env_file):
        with open(env_file) as fh:
            for line in fh:
                # The last assignment wins, as it does for docker compose.
                if line.startswith(f"{name}="):
                    value = line.split("=", 1)[1].strip()
    return value


def check_runtime(env_file):
    password = env_value("REDIS_PASSWORD", env_file)
    if not password:
        sys.exit("REDIS_PASSWORD is not set (environment or --env-file)")

    def cli(*argv):
        # `-e REDISCLI_AUTH` names the variable and nothing else: docker
        # takes its value from this process's environment. With the value
        # written after the name, as it was, the password is an argument
        # of the docker command, which every local user can read with ps
        # (#740).
        return compose(
            ["exec", "-T", "-e", "REDISCLI_AUTH", SERVICE, "redis-cli", *argv],
            env_file,
            env={**os.environ, "REDISCLI_AUTH": password},
        )

    def config_get(name):
        lines = cli("CONFIG", "GET", name).split()
        if len(lines) != 2:
            sys.exit(f"CONFIG GET {name} returned {lines!r}; wrong REDIS_PASSWORD?")
        return lines[1]

    live = {
        "maxmemory-policy": config_get("maxmemory-policy"),
        "maxmemory": config_get("maxmemory"),
        "appendonly": config_get("appendonly"),
    }
    container = compose(["ps", "-q", SERVICE], env_file).strip()
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.HostConfig.Memory}}", container],
        capture_output=True,
        text=True,
    )
    limit = r.stdout.strip() if r.returncode == 0 else None
    for k, v in live.items():
        print(f"  {k:16} {v}")
    print(f"  memory limit     {limit} bytes (docker inspect)")
    info = cli("INFO", "memory")
    for line in info.splitlines():
        if line.split(":")[0] in (
            "used_memory_human",
            "used_memory_peak_human",
            "used_memory_rss_human",
        ):
            print(f"  {line.strip()}")

    # HostConfig.Memory is 0 when the container has no limit.
    return check_settings(live, limit if limit and limit != "0" else None)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=["config", "runtime"])
    ap.add_argument("--env-file", help="env file for docker compose / REDIS_PASSWORD")
    args = ap.parse_args()
    if args.mode == "config":
        print("Rendered production Redis:")
        failures = check_config(args.env_file)
    else:
        print("Running Redis:")
        failures = check_runtime(args.env_file)
    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nRedis keeps its state: noeviction, bounded, persisted, with headroom.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
