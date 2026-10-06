"""The gateway's per-address rate limits are settings, and one set of numbers (#756).

nginx.conf defined the ``limit_req`` zones with their rates written in, so
the stacks CI starts could not raise them, and the integration suite, which
sends every request from one address, got nginx's 429 in tests that had
nothing to do with rate limiting. The rates are now three settings of the
gateway's container. ``scripts/render_rate_limits.sh`` validates them and
writes the zones into a file nginx.conf includes, before nginx starts.

The script is run here as the entrypoint runs it, with ``sh`` and nothing
else: what it writes for good values, and that it writes nothing and names
the setting for a value that is not a whole number from 1 to 100000. The
gateway harness starts real gateways with the same values
(open-security-gateway/test/startup_config_tests.sh) and measures the limits
(test/rate_limit_tests.py); what is read here are the files that have to
agree with the script: nginx.conf and the two server configurations, the
entrypoint and the test image, docker-compose.yml, .env.example, the harness
and the workflows that raise the rates for a suite.
"""

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GATEWAY = ROOT / "open-security-gateway"
SCRIPT = GATEWAY / "scripts" / "render_rate_limits.sh"
NGINX_CONF = GATEWAY / "nginx" / "nginx.conf"
SERVER_CONFS = (
    GATEWAY / "nginx" / "conf.d" / "wildbox_gateway.conf",
    GATEWAY / "nginx" / "test" / "wildbox_gateway_test.conf",
)
HARNESS = GATEWAY / "test" / "rate_limit_tests.py"

# Setting -> (zone, the rate nginx.conf had written in).
SETTINGS = {
    "GATEWAY_RATE_LIMIT_PER_SECOND": ("global", 100),
    "GATEWAY_AUTH_RATE_LIMIT_PER_SECOND": ("auth", 5),
    "GATEWAY_STATIC_RATE_LIMIT_PER_SECOND": ("static_assets", 500),
}
RENDERED = "/run/wildbox-gateway/limit_req_zones.conf"
ZONE = re.compile(r"^limit_req_zone (\S+) zone=(\w+):10m rate=(\d+)r/s;$", re.M)

# The workflows that run a suite against a stack, and so raise the rates.
SUITE_WORKFLOWS = (
    "integration-tests.yml",
    "production-stack.yml",
    "e2e-fullstack.yml",
)

spec = importlib.util.spec_from_file_location("gateway_rate_limit_harness", HARNESS)
harness = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = harness
spec.loader.exec_module(harness)


def render(tmp_path, **settings):
    """Run the script with only these settings; (process, output file)."""
    output = tmp_path / "zones" / "limit_req_zones.conf"
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    environment.update(settings)
    process = subprocess.run(
        ["sh", str(SCRIPT), str(output)],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return process, output


def zones(text):
    return {zone: (key, int(rate)) for key, zone, rate in ZONE.findall(text)}


def code(text):
    """A shell script or nginx file without its comment lines."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def defines_a_zone(text):
    """Whether an nginx file has a limit_req_zone directive of its own."""
    return re.search(r"^\s*limit_req_zone\s", code(text), re.M) is not None


# --- the script ----------------------------------------------------------------


def test_with_nothing_set_the_zones_carry_the_rates_nginx_conf_had(tmp_path):
    process, output = render(tmp_path)

    assert process.returncode == 0, process.stderr
    assert zones(output.read_text()) == {
        "global": ("$binary_remote_addr", 100),
        "auth": ("$binary_remote_addr", 5),
        "static_assets": ("$binary_remote_addr", 500),
    }
    assert (
        "Per-address request limits: global 100 r/s, auth 5 r/s, "
        "static assets 500 r/s." in process.stdout
    )


def test_the_file_holds_the_three_zones_and_no_other_directive(tmp_path):
    _process, output = render(tmp_path)

    directives = [
        line
        for line in output.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert len(directives) == 3
    assert all(ZONE.match(line) for line in directives), directives


@pytest.mark.parametrize("setting", sorted(SETTINGS))
def test_a_setting_changes_its_zone_and_only_that_one(tmp_path, setting):
    process, output = render(tmp_path, **{setting: "1234"})

    assert process.returncode == 0, process.stderr
    expected = {
        zone: ("$binary_remote_addr", 1234 if name == setting else default)
        for name, (zone, default) in SETTINGS.items()
    }
    assert zones(output.read_text()) == expected


@pytest.mark.parametrize("value", ["1", "100000"])
def test_the_ends_of_the_range_are_accepted(tmp_path, value):
    process, output = render(tmp_path, **{name: value for name in SETTINGS})

    assert process.returncode == 0, process.stderr
    assert {rate for _key, rate in zones(output.read_text()).values()} == {int(value)}


BAD_VALUES = [
    "0",
    "-5",
    "+5",
    "abc",
    "10k",
    "1.5",
    "1e3",
    " 100",
    "100 ",
    "",
    "007",
    "100001",
    "99999999999999999999",
    "5r/s",
    "5\n6",
    "5;",
    "5r/s; limit_req_zone $http_x_forwarded_for zone=global:10m rate=1",
    "$(id)",
]


@pytest.mark.parametrize("setting", sorted(SETTINGS))
@pytest.mark.parametrize("value", BAD_VALUES)
def test_a_value_that_is_not_a_whole_number_in_range_is_refused_by_name(
    tmp_path, setting, value
):
    process, output = render(tmp_path, **{setting: value})

    assert process.returncode != 0, (setting, value)
    assert (
        f"{setting} must be a whole number of requests per second "
        "between 1 and 100000" in process.stderr
    )
    # Nothing is written, and no limit is announced: nginx has no file to
    # start with, so it cannot serve with a rate nobody set.
    assert not output.exists()
    assert "Per-address request limits" not in process.stdout


def test_a_refused_value_is_not_echoed_as_it_was_given(tmp_path):
    """What is logged is a line of plain characters, whatever was set."""
    process, _output = render(
        tmp_path, GATEWAY_RATE_LIMIT_PER_SECOND="5\n[rate-limits] forged line\x1b[2J"
    )

    assert process.returncode != 0
    assert len(process.stderr.strip().splitlines()) == 1
    assert "\x1b" not in process.stderr


def test_a_refused_value_leaves_the_file_of_an_earlier_start_alone(tmp_path):
    first, output = render(tmp_path, GATEWAY_AUTH_RATE_LIMIT_PER_SECOND="7")
    assert first.returncode == 0
    before = output.read_text()

    second, _output = render(tmp_path, GATEWAY_AUTH_RATE_LIMIT_PER_SECOND="seven")

    assert second.returncode != 0
    assert output.read_text() == before
    assert not list(output.parent.glob("*.tmp"))


# --- nginx's configuration -----------------------------------------------------


def test_nginx_conf_defines_no_zone_itself_and_includes_the_rendered_file():
    text = code(NGINX_CONF.read_text())

    assert not defines_a_zone(NGINX_CONF.read_text())
    assert re.search(rf"^\s*include {re.escape(RENDERED)};$", text, re.M)
    # The path the script writes when the entrypoint runs it without one.
    assert f'OUTPUT="${{1:-{RENDERED}}}"' in SCRIPT.read_text()


def test_no_other_configuration_file_defines_a_zone():
    """A zone defined elsewhere could be keyed by something a client sends."""
    assert defines_a_zone("    limit_req_zone $http_x_real_ip zone=x:1m rate=1r/s;")
    for path in SERVER_CONFS + tuple((GATEWAY / "nginx" / "includes").glob("*.conf")):
        assert not defines_a_zone(path.read_text()), path.name


def test_every_zone_a_location_names_is_one_the_script_writes():
    written = {zone for zone, _default in SETTINGS.values()}
    for path in SERVER_CONFS:
        named = set(re.findall(r"limit_req\s+zone=(\w+)", code(path.read_text())))
        assert named, path.name
        assert named <= written, (path.name, named - written)


def test_every_zone_the_script_writes_is_used_by_the_production_configuration():
    """nginx.conf had a zone no location named (per_ip): 10 MB for nothing."""
    named = set(
        re.findall(r"limit_req\s+zone=(\w+)", code(SERVER_CONFS[0].read_text()))
    )

    assert named == {zone for zone, _default in SETTINGS.values()}


def test_a_refusal_is_answered_429_wherever_the_production_configuration_limits():
    """nginx's default for a refused request is 503."""
    text = code(SERVER_CONFS[0].read_text())
    server = text[text.index("listen 443 ssl;") :]
    limits = [match.start() for match in re.finditer(r"limit_req\s+zone=", server)]

    assert limits
    # The server-level status is inherited by every location that sets none.
    first_location = server.index("location ")
    assert re.search(r"limit_req_status 429;", server[:first_location])
    assert not re.search(r"limit_req_status (?!429;)", server)


# --- what starts nginx runs the script first -----------------------------------


def test_the_entrypoint_writes_the_zones_before_it_starts_nginx():
    text = code((GATEWAY / "scripts" / "docker-entrypoint.sh").read_text())

    assert "set -e" in text
    assert text.index("/usr/local/bin/render_rate_limits.sh") < text.index(
        "exec /usr/local/openresty/bin/openresty"
    )


def test_the_test_image_writes_them_too_and_stops_if_they_are_refused():
    text = code((GATEWAY / "Dockerfile.test").read_text())
    command = re.search(r"^CMD (.*)$", text, re.M).group(1)

    assert "render_rate_limits.sh" in text.split("CMD")[0]  # copied in
    assert re.search(r"render_rate_limits\.sh && exec .*openresty", command), command


def test_the_script_is_executable():
    assert os.access(SCRIPT, os.X_OK)


# --- one set of numbers ----------------------------------------------------------


def gateway_environment(file):
    spec = yaml.safe_load((ROOT / file).read_text(encoding="utf-8"))
    entries = spec["services"]["gateway"].get("environment") or []
    return dict(str(entry).split("=", 1) for entry in entries)


def test_compose_passes_each_setting_with_the_scripts_default():
    environment = gateway_environment("docker-compose.yml")

    for setting, (_zone, default) in SETTINGS.items():
        assert environment.get(setting) == f"${{{setting}:-{default}}}", setting


def test_the_example_env_file_holds_each_setting_at_its_default():
    """Uncommented: the workflows replace these lines in place."""
    text = (ROOT / ".env.example").read_text(encoding="utf-8")

    for setting, (_zone, default) in SETTINGS.items():
        assert re.findall(rf"^{setting}=(.*)$", text, re.M) == [str(default)], setting


def test_the_harness_measures_the_rates_the_script_defaults_to():
    assert harness.SETTINGS == tuple(SETTINGS)
    assert (harness.GLOBAL_RATE, harness.AUTH_RATE, harness.STATIC_RATE) == (
        100,
        5,
        500,
    )


def test_the_harness_knows_the_bursts_the_production_configuration_sets():
    text = code(SERVER_CONFS[0].read_text())

    def burst(location):
        block = text[text.index(location) :]
        return int(
            re.search(r"limit_req zone=\w+ burst=(\d+) nodelay;", block).group(1)
        )

    assert burst("listen 443 ssl;") == harness.GLOBAL_BURST
    assert burst("location ^~ /auth/jwt/") == harness.LOGIN_BURST
    assert burst("location ^~ /auth/register") == harness.REGISTER_BURST
    assert burst("location ^~ /auth/forgot-password") == harness.FORGOT_BURST
    assert burst("location ~ ^/(?!api/)") == harness.STATIC_BURST


# --- the stacks the suites run against -----------------------------------------


def run_steps(workflow):
    spec = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
    return "\n".join(
        step.get("run", "") for job in spec["jobs"].values() for step in job["steps"]
    )


@pytest.mark.parametrize("workflow", SUITE_WORKFLOWS)
def test_a_workflow_that_runs_a_suite_raises_the_three_rates(workflow):
    script = run_steps(workflow)

    for setting in SETTINGS:
        assert re.findall(rf"\b{setting}=(\d+)", script) == [str(harness.SUITE_RATE)], (
            workflow,
            setting,
        )
    # In place, in the .env the stack reads, and loudly if the key is gone.
    assert 'sed -i "s/^$name=.*/$setting/" .env' in script
    assert 'grep -q "^$name=" .env || {' in script


def test_the_rate_the_suites_set_is_one_the_gateway_accepts():
    assert 1 <= harness.SUITE_RATE <= 100000


def test_the_chaos_stack_keeps_the_rates_a_deployment_has():
    """Its load experiment takes a 429 from these limits as an answer."""
    script = run_steps("chaos-and-load.yml")

    assert "RATE_LIMIT_PER_HOUR=1000000" in script  # the file was read
    for setting in SETTINGS:
        assert setting not in script, setting


def test_the_gateway_workflow_runs_the_limit_tests_on_an_unset_production_image():
    workflow = ROOT / ".github" / "workflows" / "gateway-tests.yml"
    script = run_steps("gateway-tests.yml")

    assert (
        "python3 open-security-gateway/test/rate_limit_tests.py "
        "wildbox-gateway-prod gwtest gateway-prod" in script
    )
    assert (
        "startup_config_tests.sh wildbox-gateway-test gwtest wildbox-gateway-prod"
        in script
    )
    # No gateway the workflow starts by hand is given a rate: gateway-prod
    # runs with a deployment's limits.
    for setting in SETTINGS:
        assert setting not in workflow.read_text(), setting
