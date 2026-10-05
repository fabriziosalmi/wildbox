"""Tests for check_monitoring_config.py, the guard on the monitoring profile (#658).

Prometheus loaded monitoring/alert_rules.yml and had nowhere to send what
fired: prometheus.yml had no `alerting:` section and no Compose file defined
an Alertmanager. The files in the tree must pass the static checks, and each
test below breaks one thing in a copy of them and expects the check to name
it. The checks that need Docker (promtool, amtool) run in the "Code Quality"
job, not here.
"""

import copy
import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_monitoring_config.py"
spec = importlib.util.spec_from_file_location("check_monitoring_config", SCRIPT)
cmc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmc)


def load(relative):
    return yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))


@pytest.fixture
def compose():
    return load(cmc.COMPOSE_FILE)


@pytest.fixture
def prometheus():
    return load(cmc.PROMETHEUS_CONFIG)


@pytest.fixture
def rules():
    return load(cmc.ALERT_RULES)


@pytest.fixture
def rule_tests():
    return load(cmc.RULE_TESTS)


@pytest.fixture
def default_config():
    return load(cmc.ALERTMANAGER_CONFIG)


def example(name):
    return load(f"monitoring/examples/alertmanager-{name}.yml")


def one_problem(problems, *fragments):
    """Exactly one problem, mentioning every fragment."""
    assert len(problems) == 1, problems
    for fragment in fragments:
        assert fragment in problems[0], problems[0]


# --- the tree as it is -------------------------------------------------------


def test_the_shipped_files_pass_every_static_check():
    assert cmc.static_checks(ROOT) == []


def test_the_default_and_both_examples_are_checked():
    files = cmc.alertmanager_config_files(ROOT)

    assert files == [
        ("monitoring/alertmanager.yml", True),
        ("monitoring/examples/alertmanager-email.yml", False),
        ("monitoring/examples/alertmanager-webhook.yml", False),
    ]


def test_prometheus_sends_alerts_to_the_alertmanager_service(prometheus, compose):
    # The acceptance test of #658.
    assert cmc.alertmanager_targets(prometheus) == ["alertmanager:9093"]
    assert compose["services"]["alertmanager"]["profiles"] == ["monitoring"]
    assert compose["services"]["prometheus"]["profiles"] == ["monitoring"]


# --- prometheus.yml ----------------------------------------------------------


def test_no_alerting_section_fails(prometheus, compose):
    # The state of main before #658: rules evaluated, nothing sent.
    del prometheus["alerting"]

    one_problem(
        cmc.check_prometheus_config(prometheus, compose),
        "no `alerting.alertmanagers` target",
    )


def test_an_alerting_section_without_targets_fails(prometheus, compose):
    prometheus["alerting"]["alertmanagers"][0]["static_configs"][0]["targets"] = []

    one_problem(
        cmc.check_prometheus_config(prometheus, compose),
        "no `alerting.alertmanagers` target",
    )


def test_a_target_that_is_not_a_monitoring_service_fails(prometheus, compose):
    targets = prometheus["alerting"]["alertmanagers"][0]["static_configs"][0]
    targets["targets"] = ["alert-manager:9093"]

    one_problem(
        cmc.check_prometheus_config(prometheus, compose),
        "'alert-manager:9093'",
        "not a service",
    )


def test_a_target_on_a_service_outside_the_profile_fails(prometheus, compose):
    # The name resolves, but the service would not be running.
    targets = prometheus["alerting"]["alertmanagers"][0]["static_configs"][0]
    targets["targets"] = ["identity:9093"]

    one_problem(cmc.check_prometheus_config(prometheus, compose), "'identity:9093'")


def test_a_target_on_the_wrong_port_fails(prometheus, compose):
    targets = prometheus["alerting"]["alertmanagers"][0]["static_configs"][0]
    targets["targets"] = ["alertmanager:9094"]

    one_problem(
        cmc.check_prometheus_config(prometheus, compose),
        "port 9094",
        "listens on 9093",
    )


def test_the_port_follows_the_listen_address_flag(prometheus, compose):
    compose["services"]["alertmanager"]["command"].append("--web.listen-address=:9099")

    one_problem(cmc.check_prometheus_config(prometheus, compose), "listens on 9099")


def test_a_rule_file_the_container_does_not_mount_fails(prometheus, compose):
    prometheus["rule_files"] = ["/etc/prometheus/rules/*.yml"]

    one_problem(
        cmc.check_prometheus_config(prometheus, compose),
        "/etc/prometheus/rules/*.yml",
    )


def test_no_rule_files_fails(prometheus, compose):
    prometheus["rule_files"] = []

    one_problem(cmc.check_prometheus_config(prometheus, compose), "no rule_files")


# --- docker-compose.yml ------------------------------------------------------


def test_no_alertmanager_service_fails(compose):
    del compose["services"]["alertmanager"]

    one_problem(cmc.check_compose(compose), "no `alertmanager` service")


def test_alertmanager_outside_the_monitoring_profile_fails(compose):
    compose["services"]["alertmanager"]["profiles"] = ["alerting"]

    one_problem(cmc.check_compose(compose), "alertmanager: profiles")


@pytest.mark.parametrize(
    "image",
    [
        "prom/alertmanager",
        "prom/alertmanager:latest",
        "prom/alertmanager:v0.34",
        "prom/alertmanager:main",
    ],
)
def test_an_image_without_an_exact_version_fails(compose, image):
    compose["services"]["alertmanager"]["image"] = image

    one_problem(cmc.check_compose(compose), "exact version")


def test_an_exact_version_with_a_digest_passes(compose):
    compose["services"]["alertmanager"]["image"] = (
        "prom/alertmanager:v0.34.1@sha256:" + "a" * 64
    )

    assert cmc.check_compose(compose) == []


@pytest.mark.parametrize("user", [None, "root", "0", "0:0", "root:65534"])
def test_running_as_root_fails(compose, user):
    if user is None:
        del compose["services"]["alertmanager"]["user"]
    else:
        compose["services"]["alertmanager"]["user"] = user

    one_problem(cmc.check_compose(compose), "non-root")


def test_a_writable_root_filesystem_fails(compose):
    del compose["services"]["alertmanager"]["read_only"]

    one_problem(cmc.check_compose(compose), "read_only")


def test_missing_no_new_privileges_fails(compose):
    compose["services"]["alertmanager"]["security_opt"] = []

    one_problem(cmc.check_compose(compose), "no-new-privileges")


@pytest.mark.parametrize(
    "healthcheck",
    [None, {"test": ["NONE"]}, {"disable": True, "test": ["CMD", "true"]}],
)
def test_no_healthcheck_fails(compose, healthcheck):
    if healthcheck is None:
        del compose["services"]["alertmanager"]["healthcheck"]
    else:
        compose["services"]["alertmanager"]["healthcheck"] = healthcheck

    one_problem(cmc.check_compose(compose), "no healthcheck")


@pytest.mark.parametrize("limit", ["cpus", "memory"])
def test_a_missing_resource_limit_fails(compose, limit):
    del compose["services"]["alertmanager"]["deploy"]["resources"]["limits"][limit]

    one_problem(cmc.check_compose(compose), f"limits.{limit}")


@pytest.mark.parametrize("service", ["alertmanager", "prometheus"])
@pytest.mark.parametrize(
    "port", ["9093:9093", "0.0.0.0:9093:9093", {"target": 9093, "published": 9093}]
)
def test_a_port_published_beyond_loopback_fails(compose, service, port):
    compose["services"][service]["ports"] = [port]

    one_problem(cmc.check_compose(compose), service, "not bound to 127.0.0.1")


def test_a_secret_in_the_environment_fails(compose):
    compose["services"]["alertmanager"]["environment"] = [
        "SMTP_PASSWORD=${ALERTMANAGER_SMTP_PASSWORD}"
    ]

    one_problem(cmc.check_compose(compose), "environment", "docker inspect")


def test_a_secret_on_the_command_line_fails(compose):
    compose["services"]["alertmanager"]["command"].append(
        "--smtp.password=${ALERTMANAGER_SMTP_PASSWORD}"
    )

    one_problem(cmc.check_compose(compose), "${ALERTMANAGER_SMTP_PASSWORD}", "argv")


def test_the_external_url_is_the_only_variable_on_the_command_line(compose):
    command = " ".join(compose["services"]["alertmanager"]["command"])

    assert cmc.VARIABLE.findall(command) == ["ALERTMANAGER_EXTERNAL_URL"]


def test_a_configuration_that_is_not_mounted_fails(compose):
    service = compose["services"]["alertmanager"]
    service["volumes"] = [v for v in service["volumes"] if "alertmanager.yml" not in v]

    one_problem(
        cmc.check_compose(compose),
        "nothing is mounted at /etc/alertmanager/alertmanager.yml",
    )


def test_another_default_configuration_fails(compose):
    # The shipped default is the file CI validates and the docs describe.
    service = compose["services"]["alertmanager"]
    service["volumes"] = [
        v.replace(
            "./monitoring/alertmanager.yml",
            "./monitoring/examples/alertmanager-email.yml",
        )
        for v in service["volumes"]
    ]

    one_problem(cmc.check_compose(compose), "default configuration")


@pytest.mark.parametrize("target", ["alertmanager.yml", "secrets"])
def test_a_writable_configuration_or_secrets_mount_fails(compose, target):
    service = compose["services"]["alertmanager"]
    service["volumes"] = [
        v[: -len(":ro")] if v.endswith(f"/etc/alertmanager/{target}:ro") else v
        for v in service["volumes"]
    ]

    one_problem(cmc.check_compose(compose), "read-only")


def test_no_secrets_mount_fails(compose):
    service = compose["services"]["alertmanager"]
    service["volumes"] = [
        v for v in service["volumes"] if "/etc/alertmanager/secrets" not in v
    ]

    one_problem(cmc.check_compose(compose), "/etc/alertmanager/secrets")


# --- alert_rules.yml ---------------------------------------------------------


def test_a_rule_on_a_job_that_is_not_scraped_fails(rules, prometheus, rule_tests):
    # Without the scrape job the expression is empty for ever: the alert
    # loads, shows as inactive and can never fire.
    prometheus["scrape_configs"] = [
        job for job in prometheus["scrape_configs"] if job["job_name"] != "alertmanager"
    ]

    one_problem(
        cmc.check_rules(rules, prometheus, rule_tests),
        "WildboxAlertmanagerDown",
        "job='alertmanager'",
        "can never fire",
    )


@pytest.mark.parametrize("annotation", ["summary", "description"])
def test_an_alert_that_does_not_say_what_it_measures_fails(
    rules, prometheus, rule_tests, annotation
):
    rule = cmc.alert_rules(rules)[0]
    del rule["annotations"][annotation]

    one_problem(
        cmc.check_rules(rules, prometheus, rule_tests), rule["alert"], annotation
    )


def test_an_alert_without_a_severity_fails(rules, prometheus, rule_tests):
    rule = cmc.alert_rules(rules)[0]
    del rule["labels"]["severity"]

    one_problem(
        cmc.check_rules(rules, prometheus, rule_tests), rule["alert"], "severity"
    )


def test_an_alert_no_unit_test_fires_fails(rules, prometheus, rule_tests):
    extra = copy.deepcopy(cmc.alert_rules(rules)[0])
    extra["alert"] = "WildboxUntested"
    rules["groups"][0]["rules"].append(extra)

    one_problem(
        cmc.check_rules(rules, prometheus, rule_tests),
        "WildboxUntested",
        "no unit test",
    )


def test_a_test_that_only_expects_silence_is_not_a_firing_test(
    rules, prometheus, rule_tests
):
    for test in rule_tests["tests"]:
        for case in test["alert_rule_test"]:
            if case["alertname"] == "WildboxServiceDown":
                case["exp_alerts"] = []

    one_problem(
        cmc.check_rules(rules, prometheus, rule_tests),
        "WildboxServiceDown",
        "no unit test",
    )


def test_the_alert_that_fired_on_an_idle_stack_is_gone(rules):
    # WildboxNoToolExecutions fired on a healthy stack nobody had used for
    # twelve hours, and could not fire after a restart with no run.
    assert "WildboxNoToolExecutions" not in [
        rule["alert"] for rule in cmc.alert_rules(rules)
    ]


def test_an_empty_rule_file_fails(prometheus, rule_tests):
    one_problem(
        cmc.check_rules({"groups": []}, prometheus, rule_tests), "no alerting rule"
    )


# --- alertmanager.yml and the examples ---------------------------------------


def test_the_shipped_default_notifies_nobody_and_says_so(default_config):
    assert default_config["route"]["receiver"] == "no-notifications"
    assert default_config["receivers"] == [{"name": "no-notifications"}]


def test_a_silent_receiver_under_another_name_fails(default_config):
    # A receiver called `default` or `team` that sends nowhere reads as if
    # somebody were being told.
    default_config["route"]["receiver"] = "default"
    default_config["receivers"] = [{"name": "default"}]

    problems = cmc.check_alertmanager_config(default_config, "alertmanager.yml", True)

    assert len(problems) == 2, problems
    assert "'default' has no integration" in problems[0]
    assert "must route only to 'no-notifications'" in problems[1]


def test_no_notifications_with_an_integration_fails(default_config):
    default_config["receivers"][0]["webhook_configs"] = [
        {"url_file": "/etc/alertmanager/secrets/webhook_url"}
    ]

    one_problem(
        cmc.check_alertmanager_config(default_config, "alertmanager.yml", True),
        "'no-notifications' has an integration",
    )


def test_the_shipped_default_may_not_send_anywhere(default_config):
    # It cannot know an operator's mail server; a default that tried would
    # fail every notification instead of saying that none is configured.
    shipped = example("webhook")

    one_problem(
        cmc.check_alertmanager_config(shipped, "alertmanager.yml", True),
        "must route only to 'no-notifications'",
    )


def test_a_child_route_of_the_default_may_not_send_either(default_config):
    default_config["route"]["routes"] = [{"receiver": "webhook"}]
    default_config["receivers"].append(
        {
            "name": "webhook",
            "webhook_configs": [{"url_file": "/etc/alertmanager/secrets/webhook_url"}],
        }
    )

    one_problem(
        cmc.check_alertmanager_config(default_config, "alertmanager.yml", True),
        "routes to 'webhook'",
    )


def test_a_route_to_an_undefined_receiver_fails(default_config):
    default_config["route"]["receiver"] = "on-call"

    problems = cmc.check_alertmanager_config(default_config, "alertmanager.yml", True)

    assert any(
        "'on-call' is not a defined receiver" in problem for problem in problems
    ), problems


@pytest.mark.parametrize("name", ["email", "webhook"])
def test_each_example_sends_somewhere(name):
    config = example(name)

    assert cmc.check_alertmanager_config(config, f"{name}.yml", False) == []
    assert cmc.integrations(config["receivers"][0])


def test_an_example_that_sends_nowhere_fails():
    config = example("webhook")
    config["route"]["receiver"] = "no-notifications"
    config["receivers"].append({"name": "no-notifications"})

    one_problem(
        cmc.check_alertmanager_config(config, "example.yml", False), "sends nowhere"
    )


@pytest.mark.parametrize(
    "setting, value",
    [
        ("smtp_auth_password", "hunter2"),
        ("smtp_auth_secret", "hunter2"),
        ("slack_api_url", "https://hooks.slack.example/T0/B0/xyz"),
    ],
)
def test_an_inline_secret_in_global_fails(setting, value):
    config = example("email")
    config["global"][setting] = value

    one_problem(
        cmc.check_alertmanager_config(config, "example.yml", False),
        f"global.{setting}",
        "inline",
    )


def test_an_inline_webhook_url_fails():
    config = example("webhook")
    hook = config["receivers"][0]["webhook_configs"][0]
    del hook["url_file"]
    hook["url"] = "https://hooks.example.com/T0/secret-token"

    one_problem(
        cmc.check_alertmanager_config(config, "example.yml", False),
        "receivers[0].webhook_configs[0].url holds a secret inline",
    )


@pytest.mark.parametrize(
    "http_config, setting",
    [
        ({"authorization": {"credentials": "t0ken"}}, "authorization.credentials"),
        ({"basic_auth": {"username": "u", "password": "p"}}, "basic_auth.password"),
        ({"bearer_token": "t0ken"}, "bearer_token"),
        ({"oauth2": {"client_id": "id", "client_secret": "s"}}, "oauth2.client_secret"),
    ],
)
def test_an_inline_http_credential_fails(http_config, setting):
    config = example("webhook")
    config["receivers"][0]["webhook_configs"][0]["http_config"] = http_config

    one_problem(
        cmc.check_alertmanager_config(config, "example.yml", False), setting, "inline"
    )


@pytest.mark.parametrize(
    "path",
    ["/etc/alertmanager/smtp_password", "/run/secrets/smtp_password", "smtp_password"],
)
def test_a_secret_file_outside_the_mounted_directory_fails(path):
    # The container mounts one directory for secrets; a path elsewhere does
    # not exist in it, and every notification would fail.
    config = example("email")
    config["global"]["smtp_auth_password_file"] = path

    one_problem(
        cmc.check_alertmanager_config(config, "example.yml", False), path, "outside"
    )


def test_the_examples_name_only_files_under_the_mounted_directory():
    for name in ("email", "webhook"):
        _, files = cmc._inline_secrets(example(name))

        assert files, name
        assert all(value.startswith("/etc/alertmanager/secrets/") for _, value in files)


# --- reading the expressions -------------------------------------------------


def test_rule_selectors_reads_metrics_labels_and_operators():
    expr = """
    sum by (service) (rate(wildbox_http_requests_total{status=~"5.."}[5m]))
    /
    sum by (service) (rate(wildbox_http_requests_total[5m])) > 0.05
    """

    assert cmc.rule_selectors(expr) == {
        "wildbox_http_requests_total": {"status": [("=~", "5..")]}
    }
    assert cmc.rule_metric_names(expr) == {"wildbox_http_requests_total"}
    assert cmc.grouping_labels(expr) == {"service"}


@pytest.mark.parametrize(
    "expr, metrics",
    [
        ('up{job="wildbox-services"} == 0', {"up"}),
        ("some_gauge > 0", {"some_gauge"}),
        ("sum(increase(a_total[6h])) == 0", {"a_total"}),
        ("sum without (instance) (rate(a_total[5m] offset 1h))", {"a_total"}),
        (
            "a_total / on (job) group_left (version) b_info and c_up unless d_down",
            {"a_total", "b_info", "c_up", "d_down"},
        ),
        ('label_replace(a{x="b_total"}, "c", "$1", "d", "(.*)") > bool 1e3', {"a"}),
        ("histogram_quantile(0.9, sum by (le) (rate(h_bucket[5m])))", {"h_bucket"}),
        ("job:requests:rate5m > 10", {"job:requests:rate5m"}),
        ("absent(up) or vector(0)", {"up"}),
    ],
)
def test_rule_metric_names_reads_every_metric_and_nothing_else(expr, metrics):
    assert cmc.rule_metric_names(expr) == metrics


def test_the_shipped_rules_read_these_metrics(rules):
    # The audit of #658, pinned: change a rule and this says what it reads.
    read = {
        rule["alert"]: cmc.rule_metric_names(rule["expr"])
        for rule in cmc.alert_rules(rules)
    }

    assert read == {
        "WildboxServiceDown": {"up"},
        "WildboxHighErrorRate": {"wildbox_http_requests_total"},
        "WildboxSyncToolFailureRate": {"wildbox_tool_executions_total"},
        "WildboxAlertmanagerDown": {"up"},
        "WildboxAlertNotificationsFailing": {"alertmanager_notifications_failed_total"},
    }


def test_rule_selectors_reads_several_matchers():
    expr = 'up{job="wildbox-services", instance!="x"} == 0'

    assert cmc.rule_selectors(expr) == {
        "up": {"job": [("=", "wildbox-services")], "instance": [("!=", "x")]}
    }


def test_bind_mounts_use_the_compose_default_and_skip_named_volumes(compose):
    mounts = cmc.bind_mounts(compose["services"]["alertmanager"])

    assert mounts == [
        ("./monitoring/alertmanager.yml", "/etc/alertmanager/alertmanager.yml", True),
        ("./monitoring/secrets", "/etc/alertmanager/secrets", True),
    ]


# --- a running Prometheus ----------------------------------------------------


def runtime_state(rules):
    """What a healthy Prometheus of the profile reports, as the API shapes it."""
    alertmanagers = {
        "activeAlertmanagers": [{"url": "http://alertmanager:9093/api/v2/alerts"}]
    }
    groups = {
        "groups": [
            {
                "name": "all",
                "rules": [
                    {"name": rule["alert"], "health": "ok", "lastError": ""}
                    for rule in cmc.alert_rules(rules)
                ],
            }
        ]
    }
    targets = {
        "activeTargets": [
            {
                "labels": {"job": "wildbox-services", "instance": "api:8000"},
                "health": "up",
                "lastError": "",
            },
            {
                "labels": {"job": "alertmanager", "instance": "alertmanager:9093"},
                "health": "up",
                "lastError": "",
            },
        ]
    }
    metadata = {
        "wildbox_http_requests_total": [{"type": "counter"}],
        "wildbox_tool_executions_total": [{"type": "counter"}],
        "alertmanager_notifications_failed_total": [{"type": "counter"}],
    }
    return alertmanagers, groups, targets, metadata


def test_a_healthy_prometheus_passes(rules):
    assert cmc.check_runtime_state(*runtime_state(rules), rules) == []


def test_a_prometheus_without_an_alertmanager_fails(rules):
    alertmanagers, groups, targets, metadata = runtime_state(rules)
    alertmanagers["activeAlertmanagers"] = []

    one_problem(
        cmc.check_runtime_state(alertmanagers, groups, targets, metadata, rules),
        "no active Alertmanager",
    )


def test_a_target_that_is_down_fails(rules):
    alertmanagers, groups, targets, metadata = runtime_state(rules)
    targets["activeTargets"][0].update(health="down", lastError="no such host")

    one_problem(
        cmc.check_runtime_state(alertmanagers, groups, targets, metadata, rules),
        "wildbox-services/api:8000 is down",
        "no such host",
    )


@pytest.mark.parametrize(
    "metric, alert",
    [
        ("wildbox_tool_executions_total", "WildboxSyncToolFailureRate"),
        ("wildbox_http_requests_total", "WildboxHighErrorRate"),
        ("alertmanager_notifications_failed_total", "WildboxAlertNotificationsFailing"),
    ],
)
def test_a_rule_on_a_metric_no_target_exports_fails(rules, metric, alert):
    # The rule loads and evaluates to nothing: Prometheus never complains.
    alertmanagers, groups, targets, metadata = runtime_state(rules)
    del metadata[metric]

    one_problem(
        cmc.check_runtime_state(alertmanagers, groups, targets, metadata, rules),
        alert,
        metric,
        "can never fire",
    )


def test_up_needs_no_metadata(rules):
    # Prometheus writes `up` itself; no target exports it.
    _, _, _, metadata = runtime_state(rules)

    assert "up" not in metadata
    assert "up" in cmc.SYNTHETIC_METRICS


def test_a_rule_prometheus_has_not_loaded_fails(rules):
    alertmanagers, groups, targets, metadata = runtime_state(rules)
    groups["groups"][0]["rules"].pop()

    one_problem(
        cmc.check_runtime_state(alertmanagers, groups, targets, metadata, rules),
        "WildboxAlertNotificationsFailing",
        "has not loaded it",
    )


def test_a_rule_that_fails_to_evaluate_fails(rules):
    alertmanagers, groups, targets, metadata = runtime_state(rules)
    groups["groups"][0]["rules"][0].update(health="err", lastError="many-to-many")

    one_problem(
        cmc.check_runtime_state(alertmanagers, groups, targets, metadata, rules),
        "fails to evaluate",
        "many-to-many",
    )
