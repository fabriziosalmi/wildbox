#!/usr/bin/env python3
"""Verify that the monitoring profile can deliver an alert, and says so honestly (#658).

Prometheus evaluated monitoring/alert_rules.yml with no Alertmanager to send
the result to: prometheus.yml had no ``alerting:`` section and no Compose file
defined the service, so a firing alert notified nobody. Nothing checked the
rules either; a rule on a metric that does not exist loads without a word.

Two sets of checks, against the files as they are in the tree:

static   Read with PyYAML, no Docker needed.
         - docker-compose.yml: the ``monitoring`` profile defines both
           ``prometheus`` and ``alertmanager``; Alertmanager's image names an
           exact version, it runs as a non-root user on a read-only root
           filesystem with ``no-new-privileges``, has a health check and
           resource limits, publishes its port on 127.0.0.1 only, and takes
           no setting from the environment or from a variable on its command
           line other than its external URL (a secret in either is readable
           with ``docker inspect`` and ``ps``).
         - monitoring/prometheus.yml: ``alerting.alertmanagers`` names that
           service, on the port it listens on; the rule files it loads are
           the ones the container mounts; tools-worker, which serves no HTTP,
           is not a scrape target (#721).
         - monitoring/alert_rules.yml: every ``job="..."`` an expression
           selects is a scrape job; a metric that only the tools api exports
           (its own runs and, from Redis, the worker's) is read only while
           that api is scraped; every alert has a severity, a summary and a
           description, a unit test in which it fires and one in which it
           must stay silent.
         - monitoring/alertmanager.yml and monitoring/examples/*.yml: a
           receiver that sends nowhere is named ``no-notifications`` and the
           shipped default has no other; an example has a receiver that does
           send; no file holds a secret inline, only ``*_file`` settings
           under the directory the container mounts.

tools    With the images docker-compose.yml names, so the version that checks
         is the version that runs:
         - ``promtool check config`` on prometheus.yml (which also checks the
           rule files it loads) and ``promtool test rules`` on
           monitoring/alert_rules.test.yml;
         - ``amtool check-config`` on the default configuration and on every
           example, and ``amtool config routes test`` to confirm where the
           default sends each alert.

runtime  Against a running Prometheus of the profile (``--runtime URL``),
         instead of the two above:
         - it has discovered an Alertmanager and loaded every rule group
           without an evaluation error;
         - every scrape target is up (waiting for the first scrapes);
         - every metric an alert expression reads is exported by a target
           that is being scraped. This is the check on a real stack that a
           rule does not name a metric nobody exports.

Usage:
  scripts/check_monitoring_config.py            # static and tools
  scripts/check_monitoring_config.py --static   # no Docker
  scripts/check_monitoring_config.py --runtime http://127.0.0.1:9090
"""

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

COMPOSE_FILE = "docker-compose.yml"
MONITORING_DIR = "monitoring"
PROMETHEUS_CONFIG = "monitoring/prometheus.yml"
ALERT_RULES = "monitoring/alert_rules.yml"
RULE_TESTS = "monitoring/alert_rules.test.yml"
ALERTMANAGER_CONFIG = "monitoring/alertmanager.yml"
EXAMPLES_GLOB = "monitoring/examples/*.yml"

PROFILE = "monitoring"
# The receiver that has no integration. The name is the contract: an operator
# who reads `receiver: no-notifications` knows nobody is told.
SILENT_RECEIVER = "no-notifications"
# Where the container mounts ALERTMANAGER_SECRETS_DIR.
SECRETS_MOUNT = "/etc/alertmanager/secrets"
ALERTMANAGER_DEFAULT_PORT = "9093"
# Variables that may appear on Alertmanager's command line. Not secrets.
ALLOWED_COMMAND_VARIABLES = {"ALERTMANAGER_EXTERNAL_URL"}

EXACT_VERSION = re.compile(r"^[\w./-]+:v?\d+\.\d+\.\d+(@sha256:[0-9a-f]{64})?$")
VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)")
# ${NAME:-default} or ${NAME-default}: the value Compose uses when NAME is unset.
VARIABLE_DEFAULT = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^}]*)\}")
JOB_MATCHER = re.compile(r"""\bjob\s*=~?\s*["']([^"']*)["']""")
SELECTOR = re.compile(r"([a-zA-Z_:][a-zA-Z0-9_:]*)\s*\{([^}]*)\}")
LABEL_MATCHER = re.compile(
    r"""([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)\s*["']([^"']*)["']"""
)
GROUPING = re.compile(
    r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\(([^)]*)\)"
)
# Identifiers of PromQL that are not metric names and are not always followed
# by a parenthesis: aggregation operators (`sum by (x) (...)`), set and
# modifier keywords, and the special float values.
PROMQL_WORDS = {
    "sum",
    "min",
    "max",
    "avg",
    "group",
    "stddev",
    "stdvar",
    "count",
    "count_values",
    "bottomk",
    "topk",
    "quantile",
    "limitk",
    "limit_ratio",
    "by",
    "without",
    "on",
    "ignoring",
    "group_left",
    "group_right",
    "and",
    "or",
    "unless",
    "offset",
    "bool",
    "atan2",
    "inf",
    "Inf",
    "nan",
    "NaN",
}
# Series Prometheus writes itself for every target; they have no metadata.
SYNTHETIC_METRICS = {"up"}
# Metrics that one scrape target alone exports, by prefix. The tools api
# exports the counters of the runs it executes and, read from Redis, of the
# runs tools-worker executes (#721): the worker itself serves no HTTP and is
# not on a network Prometheus can reach, so it must never be the target. A
# rule on one of these fires only while that target is scraped.
SOLE_EXPORTERS = {"wildbox_tool_": "open-security-tools:8000"}
# Names that look like a place to scrape and are not one, with the reason:
# the Compose service and the alias it has on the network.
_TOOLS_WORKER = (
    "tools-worker is a Celery worker: it serves no HTTP, and on the production networks "
    "Prometheus cannot reach it, so the target would be down for ever. Its runs are "
    "exported by open-security-tools:8000 (wildbox_tool_async_*)"
)
NOT_SCRAPE_TARGETS = {
    "tools-worker": _TOOLS_WORKER,
    "open-security-tools-worker": _TOOLS_WORKER,
}

# Settings that hold a secret when written inline. Each has a `*_file`
# counterpart in Alertmanager, which is the only form the shipped files use.
INLINE_SECRET_SUFFIXES = (
    "password",
    "secret",
    "token",
    "credentials",
    "api_key",
    "routing_key",
    "service_key",
    "user_key",
)
# A webhook or chat URL carries its token in the path or the query string.
INLINE_SECRET_KEYS = {"url", "api_url", "webhook_url", "slack_api_url"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def load_yaml(path):
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def command_args(service):
    """The service's command as a list of arguments."""
    command = service.get("command")
    if isinstance(command, str):
        return command.split()
    return [str(item) for item in as_list(command)]


def flag_value(service, flag, default=None):
    """The value of ``--flag=value`` (or ``--flag value``) on the command."""
    args = command_args(service)
    for index, arg in enumerate(args):
        if arg == flag and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(flag + "="):
            return arg[len(flag) + 1 :]
    return default


def compose_default(text):
    """A Compose value with every ``${NAME:-default}`` replaced by its default."""
    return VARIABLE_DEFAULT.sub(lambda match: match.group(1), str(text))


def bind_mounts(service):
    """[(source, target, read_only)] for the service's short-form bind mounts.

    The source is what Compose uses when no variable is set; named volumes
    (no path separator in the source) are left out.
    """
    mounts = []
    for volume in as_list(service.get("volumes")):
        if isinstance(volume, dict):
            if volume.get("type") != "bind":
                continue
            source = compose_default(volume.get("source", ""))
            mounts.append(
                (source, volume.get("target", ""), bool(volume.get("read_only")))
            )
            continue
        parts = compose_default(volume).split(":")
        if len(parts) < 2 or "/" not in parts[0]:
            continue
        mounts.append((parts[0], parts[1], "ro" in parts[2:]))
    return mounts


def normalise(path):
    return str(path).removeprefix("./")


def rule_selectors(expr):
    """{metric: {label: [(operator, value), ...]}} for every ``metric{...}`` in expr."""
    found = {}
    for metric, body in SELECTOR.findall(expr):
        labels = found.setdefault(metric, {})
        for label, operator, value in LABEL_MATCHER.findall(body):
            labels.setdefault(label, []).append((operator, value))
    return found


def rule_metric_names(expr):
    """Every metric name in a PromQL expression.

    What is left of the identifiers once strings, label matchers, grouping
    clauses, durations, function calls, aggregation operators and keywords
    are taken out.
    """
    text = re.sub(r"""["'][^"']*["']""", " ", expr)
    text = re.sub(r"\{[^}]*\}", " ", text)
    text = GROUPING.sub(" ", text)
    text = re.sub(r"\[[^\]]*\]", " ", text)
    names = re.findall(r"(?<![\w.:])([a-zA-Z_:][a-zA-Z0-9_:]*)\b(?!\s*\()", text)
    return {name for name in names if name not in PROMQL_WORDS}


def grouping_labels(expr):
    """The labels an expression aggregates or joins on: ``by (a, b)``."""
    labels = set()
    for body in GROUPING.findall(expr):
        labels.update(label.strip() for label in body.split(",") if label.strip())
    return labels


def sole_exporter(metric):
    """The one scrape target that exports ``metric``, if only one does."""
    for prefix, target in SOLE_EXPORTERS.items():
        if metric.startswith(prefix):
            return target
    return None


def scrape_targets(prometheus):
    """Every ``host:port`` the scrape configuration lists."""
    targets = set()
    for job in as_list(prometheus.get("scrape_configs")):
        for static in as_list(job.get("static_configs")):
            targets.update(str(target) for target in as_list(static.get("targets")))
    return targets


def alert_rules(rules):
    """Every alerting rule in a rule file."""
    return [
        rule
        for group in as_list(rules.get("groups"))
        for rule in as_list(group.get("rules"))
        if rule.get("alert")
    ]


def integrations(receiver):
    """The receiver's ``*_configs`` entries that hold at least one integration."""
    return {
        key: value
        for key, value in receiver.items()
        if key.endswith("_configs") and value
    }


# --------------------------------------------------------------------------
# static checks; each returns a list of problems
# --------------------------------------------------------------------------


def check_compose(compose):
    problems = []
    services = compose.get("services") or {}
    for name in ("prometheus", "alertmanager"):
        service = services.get(name)
        if service is None:
            problems.append(
                f"{COMPOSE_FILE}: no `{name}` service: the {PROFILE} profile cannot deliver an alert"
            )
            continue
        if as_list(service.get("profiles")) != [PROFILE]:
            problems.append(
                f"{COMPOSE_FILE}: {name}: profiles must be exactly [{PROFILE}], so the two start together"
            )
        image = str(service.get("image", ""))
        if not EXACT_VERSION.match(image):
            problems.append(
                f"{COMPOSE_FILE}: {name}: image {image!r} does not name an exact version (x.y.z)"
            )
        for port in as_list(service.get("ports")):
            host_ip = (
                port.get("host_ip", "")
                if isinstance(port, dict)
                else str(port).split(":")[0]
            )
            if host_ip != "127.0.0.1":
                problems.append(
                    f"{COMPOSE_FILE}: {name}: port {port!r} is not bound to 127.0.0.1; "
                    "its UI and API have no authentication"
                )
    alertmanager = services.get("alertmanager")
    if alertmanager is not None:
        problems += _check_alertmanager_service(alertmanager)
    return problems


def _check_alertmanager_service(service):
    problems = []
    where = f"{COMPOSE_FILE}: alertmanager"

    user = str(service.get("user", "")).split(":")[0]
    if user in ("", "0", "root"):
        problems.append(
            f"{where}: `user` must name a non-root user (got {service.get('user')!r})"
        )
    if service.get("read_only") is not True:
        problems.append(
            f"{where}: `read_only: true` is missing; nothing is written outside the data volume"
        )
    if "no-new-privileges:true" not in as_list(service.get("security_opt")):
        problems.append(f"{where}: security_opt must contain no-new-privileges:true")

    healthcheck = service.get("healthcheck") or {}
    test = as_list(healthcheck.get("test"))
    if not test or test[0] == "NONE" or healthcheck.get("disable"):
        problems.append(f"{where}: no healthcheck")

    limits = ((service.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    for key in ("cpus", "memory"):
        if not limits.get(key):
            problems.append(f"{where}: deploy.resources.limits.{key} is missing")

    if service.get("environment") or service.get("env_file"):
        problems.append(
            f"{where}: has `environment`/`env_file`; Alertmanager reads no setting from the environment, "
            "and a secret there is readable with `docker inspect`. Use a *_file setting"
        )
    for arg in command_args(service) + as_list(service.get("entrypoint")):
        for variable in VARIABLE.findall(str(arg)):
            if variable not in ALLOWED_COMMAND_VARIABLES:
                problems.append(
                    f"{where}: the command line takes ${{{variable}}}; argv is readable by anyone who can list "
                    "processes, so only non-secret settings may be passed that way"
                )

    config_path = flag_value(
        service, "--config.file", "/etc/alertmanager/alertmanager.yml"
    )
    mounts = bind_mounts(service)
    config_mounts = [m for m in mounts if m[1] == config_path]
    if not config_mounts:
        problems.append(f"{where}: nothing is mounted at {config_path} (--config.file)")
    else:
        source, _, read_only = config_mounts[0]
        if normalise(source) != ALERTMANAGER_CONFIG:
            problems.append(
                f"{where}: the default configuration is {source!r}, expected ./{ALERTMANAGER_CONFIG}"
            )
        if not read_only:
            problems.append(
                f"{where}: the configuration file must be mounted read-only"
            )
    secret_mounts = [m for m in mounts if m[1] == SECRETS_MOUNT]
    if not secret_mounts:
        problems.append(
            f"{where}: no directory is mounted at {SECRETS_MOUNT}, where the examples read secrets"
        )
    elif not secret_mounts[0][2]:
        problems.append(f"{where}: {SECRETS_MOUNT} must be mounted read-only")
    return problems


def alertmanager_port(compose):
    service = (compose.get("services") or {}).get("alertmanager") or {}
    listen = flag_value(
        service, "--web.listen-address", ":" + ALERTMANAGER_DEFAULT_PORT
    )
    return listen.rsplit(":", 1)[-1]


def alertmanager_targets(prometheus):
    targets = []
    for entry in as_list((prometheus.get("alerting") or {}).get("alertmanagers")):
        for static in as_list(entry.get("static_configs")):
            targets += [str(target) for target in as_list(static.get("targets"))]
    return targets


def check_prometheus_config(prometheus, compose):
    problems = []
    services = compose.get("services") or {}

    targets = alertmanager_targets(prometheus)
    if not targets:
        problems.append(
            f"{PROMETHEUS_CONFIG}: no `alerting.alertmanagers` target: the rules are evaluated "
            "and a firing alert is sent nowhere"
        )
    port = alertmanager_port(compose)
    for target in targets:
        host, _, target_port = target.rpartition(":")
        service = services.get(host)
        if service is None or PROFILE not in as_list(service.get("profiles")):
            problems.append(
                f"{PROMETHEUS_CONFIG}: Alertmanager target {target!r} is not a service of the "
                f"{PROFILE} profile in {COMPOSE_FILE}"
            )
        elif target_port != port:
            problems.append(
                f"{PROMETHEUS_CONFIG}: Alertmanager target {target!r} uses port {target_port}; "
                f"the service listens on {port}"
            )

    for target in sorted(scrape_targets(prometheus)):
        host = target.rpartition(":")[0] or target
        if host in NOT_SCRAPE_TARGETS:
            problems.append(
                f"{PROMETHEUS_CONFIG}: scrape target {target!r}: {NOT_SCRAPE_TARGETS[host]}"
            )

    rule_files = [str(path) for path in as_list(prometheus.get("rule_files"))]
    if not rule_files:
        problems.append(f"{PROMETHEUS_CONFIG}: no rule_files")
    mounted = {
        target: source
        for source, target, _ in bind_mounts(services.get("prometheus") or {})
    }
    for path in rule_files:
        if normalise(mounted.get(path, "")) != ALERT_RULES:
            problems.append(
                f"{PROMETHEUS_CONFIG}: rule file {path} is not ./{ALERT_RULES} "
                f"mounted by the prometheus service in {COMPOSE_FILE}"
            )
    return problems


def check_rules(rules, prometheus, rule_tests):
    problems = []
    jobs = {
        str(job.get("job_name")) for job in as_list(prometheus.get("scrape_configs"))
    }
    alerts = alert_rules(rules)
    if not alerts:
        problems.append(f"{ALERT_RULES}: no alerting rule")

    scraped = scrape_targets(prometheus)

    fires_in_a_test = set()
    silent_in_a_test = set()
    for test in as_list(rule_tests.get("tests")):
        for case in as_list(test.get("alert_rule_test")):
            if case.get("exp_alerts"):
                fires_in_a_test.add(case.get("alertname"))
            else:
                silent_in_a_test.add(case.get("alertname"))

    for rule in alerts:
        name = rule["alert"]
        expr = str(rule.get("expr", ""))
        for job in JOB_MATCHER.findall(expr):
            if job not in jobs:
                problems.append(
                    f"{ALERT_RULES}: {name} selects job={job!r}, which {PROMETHEUS_CONFIG} does not scrape "
                    f"(jobs: {sorted(jobs)}): the alert can never fire"
                )
        for metric in sorted(rule_metric_names(expr)):
            exporter = sole_exporter(metric)
            if exporter and exporter not in scraped:
                problems.append(
                    f"{ALERT_RULES}: {name} reads {metric}, which only {exporter} exports, and "
                    f"{PROMETHEUS_CONFIG} does not scrape that target: the alert can never fire"
                )
        if not (rule.get("labels") or {}).get("severity"):
            problems.append(f"{ALERT_RULES}: {name} has no severity label")
        annotations = rule.get("annotations") or {}
        for key in ("summary", "description"):
            if not str(annotations.get(key, "")).strip():
                problems.append(
                    f"{ALERT_RULES}: {name} has no {key}: say what it measures"
                )
        if name not in fires_in_a_test:
            problems.append(
                f"{ALERT_RULES}: {name} has no unit test in {RULE_TESTS} in which it fires"
            )
        elif name not in silent_in_a_test:
            # An expression that is always true passes every firing test.
            problems.append(
                f"{ALERT_RULES}: {name} has no unit test in {RULE_TESTS} in which it must stay "
                "silent (`exp_alerts: []`): nothing shows what it does not fire for"
            )
    return problems


def _inline_secrets(node, trail=""):
    """Paths of settings that hold a secret inline, and of *_file settings."""
    inline, files = [], []
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{trail}.{key}" if trail else str(key)
            if isinstance(value, (dict, list)):
                found_inline, found_files = _inline_secrets(value, path)
                inline += found_inline
                files += found_files
            elif str(key).endswith("_file"):
                files.append((path, str(value)))
            elif str(key) in INLINE_SECRET_KEYS or str(key).endswith(
                INLINE_SECRET_SUFFIXES
            ):
                inline.append(path)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            found_inline, found_files = _inline_secrets(item, f"{trail}[{index}]")
            inline += found_inline
            files += found_files
    return inline, files


def _route_receivers(route):
    names = [route.get("receiver")] if route.get("receiver") else []
    for child in as_list(route.get("routes")):
        names += _route_receivers(child)
    return names


def check_alertmanager_config(config, path, shipped_default):
    """Problems in one Alertmanager configuration file.

    shipped_default: the file is monitoring/alertmanager.yml, which must
    notify nobody. Otherwise it is an example, which must notify somebody.
    """
    problems = []
    receivers = {
        r.get("name"): r
        for r in as_list(config.get("receivers"))
        if isinstance(r, dict)
    }
    route = config.get("route") or {}
    root = route.get("receiver")
    if root not in receivers:
        problems.append(f"{path}: route.receiver {root!r} is not a defined receiver")

    for name, receiver in receivers.items():
        sends = bool(integrations(receiver))
        if not sends and name != SILENT_RECEIVER:
            problems.append(
                f"{path}: receiver {name!r} has no integration and sends nowhere; "
                f"a receiver that notifies nobody must be named {SILENT_RECEIVER!r}"
            )
        if sends and name == SILENT_RECEIVER:
            problems.append(
                f"{path}: receiver {SILENT_RECEIVER!r} has an integration; rename it for what it does"
            )

    if shipped_default:
        for name in _route_receivers(route):
            if name != SILENT_RECEIVER:
                problems.append(
                    f"{path}: the shipped default routes to {name!r}; it must route only to "
                    f"{SILENT_RECEIVER!r}, because it cannot know where an operator wants to be notified"
                )
    elif root in receivers and not integrations(receivers[root]):
        problems.append(
            f"{path}: the example's default receiver {root!r} sends nowhere"
        )

    inline, files = _inline_secrets(config)
    for setting in inline:
        problems.append(
            f"{path}: {setting} holds a secret inline; a shipped configuration uses the *_file "
            f"setting and a file under {SECRETS_MOUNT}"
        )
    for setting, value in files:
        if not value.startswith(SECRETS_MOUNT + "/"):
            problems.append(
                f"{path}: {setting} is {value!r}, outside {SECRETS_MOUNT}/, the only directory "
                "the container mounts for secrets"
            )
    return problems


def alertmanager_config_files(root):
    """[(relative path, is the shipped default)]."""
    examples = sorted(str(path.relative_to(root)) for path in root.glob(EXAMPLES_GLOB))
    return [(ALERTMANAGER_CONFIG, True)] + [(example, False) for example in examples]


def static_checks(root):
    compose = load_yaml(root / COMPOSE_FILE)
    prometheus = load_yaml(root / PROMETHEUS_CONFIG)
    rules = load_yaml(root / ALERT_RULES)
    rule_tests = load_yaml(root / RULE_TESTS)

    problems = check_compose(compose)
    problems += check_prometheus_config(prometheus, compose)
    problems += check_rules(rules, prometheus, rule_tests)
    files = alertmanager_config_files(root)
    if len(files) < 2:
        problems.append(f"{EXAMPLES_GLOB}: no example configuration found")
    for path, shipped_default in files:
        problems += check_alertmanager_config(
            load_yaml(root / path), path, shipped_default
        )
    return problems


# --------------------------------------------------------------------------
# tool checks: promtool and amtool from the images the Compose file names
# --------------------------------------------------------------------------


def run_tool(image, entrypoint, args, mounts, workdir=None):
    """Run one tool in a container without network. Returns (ok, output)."""
    command = ["docker", "run", "--rm", "--network", "none"]
    for source, target in mounts:
        command += ["-v", f"{source}:{target}:ro"]
    if workdir:
        command += ["-w", workdir]
    command += ["--entrypoint", entrypoint, image] + list(args)
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def tool_checks(root):
    problems = []
    compose = load_yaml(root / COMPOSE_FILE)
    services = compose.get("services") or {}
    prometheus_image = (services.get("prometheus") or {}).get("image")
    alertmanager_image = (services.get("alertmanager") or {}).get("image")
    if not prometheus_image or not alertmanager_image:
        return [
            f"{COMPOSE_FILE}: prometheus and alertmanager must both name an image to run the tools from"
        ]

    def report(label, ok, output):
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
        if not ok:
            problems.append(f"{label} failed:\n{output}")

    # The configuration and the rule files where the container sees them.
    prometheus_service = services["prometheus"]
    config_path = flag_value(
        prometheus_service, "--config.file", "/etc/prometheus/prometheus.yml"
    )
    mounts = [
        (str((root / normalise(source)).resolve()), target)
        for source, target, _ in bind_mounts(prometheus_service)
    ]
    ok, output = run_tool(
        prometheus_image, "promtool", ["check", "config", config_path], mounts
    )
    report(
        f"promtool check config {PROMETHEUS_CONFIG} ({prometheus_image})", ok, output
    )

    monitoring = [(str((root / MONITORING_DIR).resolve()), "/monitoring")]
    ok, output = run_tool(
        prometheus_image,
        "promtool",
        ["test", "rules", Path(RULE_TESTS).name],
        monitoring,
        workdir="/monitoring",
    )
    report(f"promtool test rules {RULE_TESTS}", ok, output)

    for path, shipped_default in alertmanager_config_files(root):
        inside = "/" + path
        ok, output = run_tool(
            alertmanager_image, "amtool", ["check-config", inside], monitoring
        )
        report(f"amtool check-config {path} ({alertmanager_image})", ok, output)
        if not (ok and shipped_default):
            continue
        # Where Alertmanager itself sends each shipped alert with the default file.
        for rule in alert_rules(load_yaml(root / ALERT_RULES)):
            labels = [f"alertname={rule['alert']}"]
            labels += [
                f"{key}={value}" for key, value in (rule.get("labels") or {}).items()
            ]
            ok, output = run_tool(
                alertmanager_image,
                "amtool",
                ["config", "routes", "test", f"--config.file={inside}"] + labels,
                monitoring,
            )
            routed_to = output.splitlines()[-1].strip() if output else ""
            report(
                f"amtool config routes test {rule['alert']} -> {routed_to or '?'}",
                ok and routed_to == SILENT_RECEIVER,
                f"{output}\nexpected the default configuration to route it to {SILENT_RECEIVER}",
            )
    return problems


# --------------------------------------------------------------------------
# runtime checks: a running Prometheus of the profile
# --------------------------------------------------------------------------


def http_get_json(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.load(response)


def check_runtime_state(alertmanagers, rule_groups, targets, metadata, rules):
    """Problems in what a running Prometheus reports.

    alertmanagers, rule_groups, targets: the ``data`` of /api/v1/alertmanagers,
    /api/v1/rules and /api/v1/targets. metadata: the ``data`` of
    /api/v1/metadata, {metric: [...]} for every metric a scraped target
    exports. rules: the parsed rule file the expressions are read from.
    """
    problems = []
    if not as_list(alertmanagers.get("activeAlertmanagers")):
        problems.append(
            "Prometheus has no active Alertmanager: a firing alert is sent nowhere"
        )

    loaded = set()
    for group in as_list(rule_groups.get("groups")):
        for rule in as_list(group.get("rules")):
            loaded.add(rule.get("name"))
            if rule.get("health") == "err":
                problems.append(
                    f"rule {rule.get('name')} fails to evaluate: {rule.get('lastError')}"
                )
    for rule in alert_rules(rules):
        if rule["alert"] not in loaded:
            problems.append(
                f"rule {rule['alert']} is in {ALERT_RULES} but Prometheus has not loaded it"
            )

    for target in as_list(targets.get("activeTargets")):
        if target.get("health") != "up":
            labels = target.get("labels") or {}
            problems.append(
                f"scrape target {labels.get('job')}/{labels.get('instance')} is "
                f"{target.get('health')}: {target.get('lastError')}"
            )

    for rule in alert_rules(rules):
        for metric in sorted(rule_metric_names(str(rule.get("expr", "")))):
            if metric in SYNTHETIC_METRICS or metadata.get(metric):
                continue
            problems.append(
                f"{ALERT_RULES}: {rule['alert']} reads {metric}, which no scraped target "
                "exports: the alert can never fire"
            )
    return problems


def runtime_checks(root, url, wait_seconds):
    """Check a running Prometheus, waiting for its first scrapes."""
    url = url.rstrip("/")
    rules = load_yaml(root / ALERT_RULES)
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            state = [
                http_get_json(f"{url}/api/v1/{path}")["data"]
                for path in ("alertmanagers", "rules", "targets", "metadata")
            ]
            problems = check_runtime_state(*state, rules)
        except (OSError, ValueError, KeyError) as error:
            problems = [f"cannot read {url}: {error}"]
        if not problems or time.monotonic() >= deadline:
            break
        time.sleep(5)
    if not problems:
        targets = state[2]["activeTargets"]
        print(
            f"  ok   {len(targets)} target(s) up: "
            + ", ".join(sorted(t["labels"]["instance"] for t in targets))
        )
        print(
            "  ok   Alertmanager: "
            + ", ".join(a["url"] for a in state[0]["activeAlertmanagers"])
        )
        metrics = sorted(
            {m for rule in alert_rules(rules) for m in rule_metric_names(rule["expr"])}
        )
        print("  ok   every rule loaded; metrics read: " + ", ".join(metrics))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--static", action="store_true", help="skip the checks that need Docker"
    )
    parser.add_argument(
        "--runtime",
        metavar="URL",
        help="check a running Prometheus at URL instead of the files",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=120,
        help="with --runtime: seconds to wait for every target to be scraped (default 120)",
    )
    parser.add_argument(
        "--root", default=str(ROOT), help="repository root (default: this checkout)"
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    if args.runtime:
        print(f"Runtime checks against {args.runtime}:")
        problems = runtime_checks(root, args.runtime, args.wait)
        return report(problems)

    print("Static checks:")
    problems = static_checks(root)
    print(
        f"  {'ok  ' if not problems else 'FAIL'} compose, prometheus, rules and Alertmanager files"
    )
    if not args.static:
        print("Tool checks:")
        problems += tool_checks(root)
    return report(problems)


def report(problems):
    if problems:
        print(
            f"\nERROR: {len(problems)} monitoring configuration problem(s):",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("\nOK: the monitoring profile is consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
