#!/usr/bin/env python3
"""The gateway's per-address request limits (#756).

Run against the PRODUCTION image (Dockerfile, nginx/conf.d/wildbox_gateway.conf)
wired to test/mock_identity.py, as .github/workflows/gateway-tests.yml starts
it: with none of the three settings below, so with the limits a deployment
has.

nginx refuses a client address that sends too fast, before authentication:
``limit_req`` with the zones scripts/render_rate_limits.sh writes at start.

    GATEWAY_RATE_LIMIT_PER_SECOND         global         100 r/s, burst 10
    GATEWAY_AUTH_RATE_LIMIT_PER_SECOND    auth             5 r/s, burst 3 / 2
    GATEWAY_STATIC_RATE_LIMIT_PER_SECOND  static_assets  500 r/s, burst 200

The rates were literals in nginx.conf, so the stacks CI starts could not
raise them, and the integration suite, which sends every request from one
address, got nginx's 429 in tests that had nothing to do with rate limiting.
The rates are settings now, and the suites raise them. That leaves nothing
in the suites that meets the limits a deployment has, so they are pinned
here:

* with nothing set, the zones carry the production rates;
* a volley from one address is refused past the burst, and a steady stream
  is held to the rate: both bounds are checked, so a rate that is twice or
  half the production one fails, for the global zone and for the auth zone;
* a refusal is 429, nginx's own answer, and the number the client received
  is the number nginx logged for that zone and no other: the per-team limit
  (Lua, also 429) and identity's lockout (429 too) are different answers and
  are not counted as this one;
* the limit runs before authentication: requests without a credential are
  counted, and the ones let through are answered 401;
* what the gateway answers before the limit runs is not counted: a refused
  method, a preflight, /health and the 404 of an unknown API path take
  nothing from the address's allowance;
* login, registration and forgotten password share one counter;
* static assets are not under the global limit;
* a gateway started with the rates the CI stacks set lets through the
  sequences that are refused at the production rates.

The settings themselves (a value that is not a whole number in range stops
the gateway) are checked by startup_config_tests.sh.

Usage: rate_limit_tests.py <production image> <docker network> [container]

The container (default: gateway-prod) must publish port 443 on the host. The
script starts one more gateway from the image, on the network, with the
raised rates, and removes it.
"""

import http.client
import json
import math
import os
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter

# What a deployment has when it sets nothing: scripts/render_rate_limits.sh.
GLOBAL_RATE, GLOBAL_BURST = 100, 10
AUTH_RATE = 5
LOGIN_BURST, REGISTER_BURST, FORGOT_BURST = 3, 2, 2
STATIC_RATE, STATIC_BURST = 500, 200

# What the workflows that run a suite against a stack set for all three
# (tests/scripts/test_gateway_rate_limit_settings.py holds them to it).
SUITE_RATE = 10000
# Between two requests to an auth route at the suite rates: see where it is
# used. Two milliseconds apart is five hundred a second.
SUITE_PAUSE = 0.002

SETTINGS = (
    "GATEWAY_RATE_LIMIT_PER_SECOND",
    "GATEWAY_AUTH_RATE_LIMIT_PER_SECOND",
    "GATEWAY_STATIC_RATE_LIMIT_PER_SECOND",
)
ZONES_FILE = "/run/wildbox-gateway/limit_req_zones.conf"
ERROR_LOG = "/var/log/nginx/error.log"

# Under the global limit, answered by the gateway itself: without a
# credential authenticate() answers 401 and calls nobody, so the pace is the
# gateway's own and no team's budget is touched.
GLOBAL_PATH = "/api/v1/tools"
LOGIN = "/auth/jwt/login"
REGISTER = "/auth/register"
FORGOT = "/auth/forgot-password"

PASSED = 0
FAILED = 0


def passed(message):
    global PASSED
    PASSED += 1
    print(f"✅ {message}")


def failed(message):
    global FAILED
    FAILED += 1
    print(f"❌ {message}")


def check(condition, message, detail=""):
    if condition:
        passed(message)
    else:
        failed(f"{message}{' — ' + detail if detail else ''}")
    return condition


def docker(*arguments, check_exit=True):
    result = subprocess.run(
        ["docker", *arguments], capture_output=True, text=True, check=False
    )
    if check_exit and result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(arguments)}: {result.stderr.strip()}")
    return result.stdout + result.stderr


class Gateway:
    """One gateway container, reached on the port it publishes for 443."""

    def __init__(self, container):
        self.container = container
        published = docker("port", container, "443/tcp").split()[0]
        self.port = int(published.rsplit(":", 1)[1])
        # The certificate the container generated for itself names 127.0.0.1.
        # It is the one thing trusted here, so TLS is verified, the name
        # included, and nothing is turned off.
        certificate = docker("exec", container, "cat", "/etc/ssl/wildbox/wildbox.crt")
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls.load_verify_locations(cadata=certificate)

    def connection(self):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=self.tls, timeout=30
        )
        connection.connect()
        return connection

    def environment(self):
        entries = json.loads(
            docker("inspect", "--format", "{{json .Config.Env}}", self.container)
        )
        return dict(entry.split("=", 1) for entry in entries if "=" in entry)

    def listed_origin(self):
        """The first origin of the container's CORS_ORIGINS, or ""."""
        listed = self.environment().get("CORS_ORIGINS", "")
        return listed.split(",")[0].strip()

    def refusals(self, zone):
        """How many requests nginx has logged as refused by the zone."""
        return int(
            docker(
                "exec",
                self.container,
                "sh",
                "-c",
                f"grep -c 'limiting requests, excess: .* by zone \"{zone}\"' "
                f"{ERROR_LOG} 2>/dev/null || true",
            ).strip()
            or 0
        )


class Answer:
    def __init__(self, response, body):
        self.status = response.status
        self.body = body
        self.headers = {name.lower(): value for name, value in response.getheaders()}

    def is_nginx_limit(self):
        """nginx's own 429: not the per-team limit's, not a service's."""
        return (
            self.status == 429
            and b"429 Too Many Requests" in self.body
            and self.headers.get("content-type", "").startswith("text/html")
            and "x-ratelimit-limit" not in self.headers
            and "retry-after" not in self.headers
        )


class Outcome:
    def __init__(self, answers, elapsed):
        self.answers = answers
        self.elapsed = elapsed
        self.statuses = Counter(answer.status for answer in answers)
        self.limited = [answer for answer in answers if answer.is_nginx_limit()]

    def count(self, status):
        return self.statuses.get(status, 0)

    def describe(self):
        statuses = ", ".join(
            f"{count} x {status}" for status, count in sorted(self.statuses.items())
        )
        return f"{statuses} in {self.elapsed * 1000:.0f} ms"


def ask(connection, method, path, headers=None):
    body = b"{}" if method == "POST" else None
    sent = {"Content-Type": "application/json"} if body else {}
    sent.update(headers or {})
    connection.request(method, path, body=body, headers=sent)
    response = connection.getresponse()
    return Answer(response, response.read())


def volley(gateway, method, path, count, headers=None):
    """``count`` requests at once: a connection each, opened beforehand."""
    connections = [gateway.connection() for _ in range(count)]
    answers = [None] * count
    start = threading.Event()

    def one(index):
        start.wait()
        answers[index] = ask(connections[index], method, path, headers)

    threads = [threading.Thread(target=one, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    began = time.monotonic()
    start.set()
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - began
    for connection in connections:
        connection.close()
    return Outcome(answers, elapsed)


def stream(gateway, method, path, seconds, connections=4, pause=0.0):
    """Requests one after another on each connection, for ``seconds``."""
    answers = []
    lock = threading.Lock()
    opened = [gateway.connection() for _ in range(connections)]
    start = threading.Event()
    deadline = []

    def one(connection):
        mine = []
        start.wait()
        while time.monotonic() < deadline[0]:
            mine.append(ask(connection, method, path))
            if pause:
                time.sleep(pause)
        with lock:
            answers.extend(mine)

    threads = [threading.Thread(target=one, args=(c,)) for c in opened]
    for thread in threads:
        thread.start()
    began = time.monotonic()
    deadline.append(began + seconds)
    start.set()
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - began
    for connection in opened:
        connection.close()
    return Outcome(answers, elapsed)


def sequence(gateway, method, path, count, pause=0.0):
    """``count`` requests on one connection, as fast as it answers, or
    ``pause`` seconds apart."""
    connection = gateway.connection()
    began = time.monotonic()
    answers = []
    for _ in range(count):
        answers.append(ask(connection, method, path))
        if pause:
            time.sleep(pause)
    elapsed = time.monotonic() - began
    connection.close()
    return Outcome(answers, elapsed)


def quiet(seconds=1.5):
    """Long enough for every zone to forget what was sent before."""
    time.sleep(seconds)


# How far from the rate a measured count may be. nginx counts in
# milliseconds, on a clock each worker process keeps for itself, so over a
# few seconds it lets through a little more or less than rate x time; a rate
# that is half or twice the expected one is far outside this.
TOLERANCE = 0.25


def most_let_through(rate, burst, elapsed):
    """What the limit lets through in ``elapsed`` seconds, at most.

    The burst and the request that found the counter empty, then ``rate`` a
    second, with the tolerance.
    """
    return burst + 1 + math.ceil((1 + TOLERANCE) * rate * elapsed) + 1


def least_let_through(rate, burst, elapsed):
    """What a stream faster than the rate gets through, at least."""
    return math.floor((1 - TOLERANCE) * (burst + 1 + rate * elapsed))


def only(outcome, *statuses):
    return set(outcome.statuses) <= set(statuses)


# --- the production rates are what an unset gateway has -----------------------


def test_defaults(gateway):
    names = set(gateway.environment())
    check(
        not names & set(SETTINGS),
        f"{gateway.container} is started with none of the rate settings",
        f"set: {sorted(names & set(SETTINGS))}",
    )
    log = docker("logs", gateway.container)
    expected = (
        f"Per-address request limits: global {GLOBAL_RATE} r/s, "
        f"auth {AUTH_RATE} r/s, static assets {STATIC_RATE} r/s."
    )
    check(expected in log, f"it reports the production rates at start ({expected})")
    zones = dict(
        re.findall(
            r"^limit_req_zone \$binary_remote_addr zone=(\w+):10m rate=(\d+)r/s;$",
            docker("exec", gateway.container, "cat", ZONES_FILE),
            re.M,
        )
    )
    wanted = {
        "global": str(GLOBAL_RATE),
        "auth": str(AUTH_RATE),
        "static_assets": str(STATIC_RATE),
    }
    check(
        zones == wanted,
        "the zones nginx loads are global, auth and static_assets at those rates, "
        "keyed by the address of the connection",
        f"found {zones}",
    )


# --- what is answered before the limit is not counted -------------------------


def test_early_answers_are_not_counted(gateway):
    quiet()
    before = gateway.refusals("global")
    origin = gateway.listed_origin()
    if not check(
        bool(origin),
        f"{gateway.container} lists an origin in CORS_ORIGINS, for the preflight",
        "start it as .github/workflows/gateway-tests.yml does",
    ):
        return
    early = (
        ("a refused method", "OPTIONS", GLOBAL_PATH, None, 405),
        (
            "a preflight",
            "OPTIONS",
            GLOBAL_PATH,
            {"Origin": origin, "Access-Control-Request-Method": "GET"},
            204,
        ),
        ("/health", "GET", "/health", None, 200),
        ("an unknown API path", "GET", "/api/v1/no-such-service/x", None, 404),
    )
    for name, method, path, headers, status in early:
        outcome = volley(gateway, method, path, 40, headers)
        check(
            only(outcome, status),
            f"40 at once, {name}: each answered {status}, none limited",
            outcome.describe(),
        )
    # 160 requests in a moment. Had they been counted, the address would be
    # far past its burst and this volley, sent at once, would be refused.
    outcome = volley(gateway, "GET", GLOBAL_PATH, GLOBAL_BURST + 1)
    check(
        only(outcome, 401),
        f"right after them, {GLOBAL_BURST + 1} requests at once are all let through: "
        "the address's allowance was not touched",
        outcome.describe(),
    )
    check(
        gateway.refusals("global") == before,
        "nginx logged no refusal by the global zone for any of them",
    )


# --- the global zone ----------------------------------------------------------------


def test_global_zone(gateway):
    quiet()
    refused_before = {zone: gateway.refusals(zone) for zone in ("global", "auth")}

    count = 80
    outcome = volley(gateway, "GET", GLOBAL_PATH, count)
    let_through = outcome.count(401)
    most = most_let_through(GLOBAL_RATE, GLOBAL_BURST, outcome.elapsed)
    check(
        only(outcome, 401, 429),
        f"global, {count} at once without a credential: each is answered 401 "
        "(let through to authentication) or 429",
        outcome.describe(),
    )
    check(
        let_through >= GLOBAL_BURST + 1,
        f"global: the burst is let through ({let_through} of {count}, "
        f"at least {GLOBAL_BURST + 1})",
        outcome.describe(),
    )
    check(
        let_through <= most and outcome.count(429) >= 1,
        f"global: the rest is refused ({outcome.count(429)} x 429; at most {most} "
        f"could pass in {outcome.elapsed * 1000:.0f} ms at {GLOBAL_RATE} r/s)",
        outcome.describe(),
    )
    volley_limited = outcome

    quiet()
    seconds = 3
    outcome = stream(gateway, "GET", GLOBAL_PATH, seconds, connections=6, pause=0.002)
    let_through = outcome.count(401)
    most = most_let_through(GLOBAL_RATE, GLOBAL_BURST, outcome.elapsed)
    least = least_let_through(GLOBAL_RATE, GLOBAL_BURST, outcome.elapsed)
    check(
        only(outcome, 401, 429) and least <= let_through <= most,
        f"global, a stream of {len(outcome.answers)} requests in "
        f"{outcome.elapsed:.1f} s: {let_through} let through, which is "
        f"{GLOBAL_RATE} r/s (between {least} and {most})",
        outcome.describe(),
    )

    limited = volley_limited.limited + outcome.limited
    received = volley_limited.count(429) + outcome.count(429)
    check(
        len(limited) == received,
        f"global: every one of the {received} refusals is nginx's own 429, "
        "not the per-team limit's and not a service's",
        f"{received - len(limited)} were another 429",
    )
    logged = gateway.refusals("global") - refused_before["global"]
    check(
        logged == received,
        f"global: the client received {received} refusals and nginx logged "
        f"{logged} by the global zone",
    )
    check(
        gateway.refusals("auth") == refused_before["auth"],
        "global: none of them was counted by the auth zone",
    )

    quiet()
    outcome = volley(gateway, "GET", GLOBAL_PATH, GLOBAL_BURST + 1)
    check(
        only(outcome, 401),
        "global: a second later the address is served again",
        outcome.describe(),
    )


# --- the auth zone ----------------------------------------------------------------


def test_auth_zone(gateway):
    refused_before = {zone: gateway.refusals(zone) for zone in ("global", "auth")}
    received = 0
    limited = 0

    for name, path, burst in (
        ("login", LOGIN, LOGIN_BURST),
        ("registration", REGISTER, REGISTER_BURST),
        ("forgotten password", FORGOT, FORGOT_BURST),
    ):
        quiet()
        count = 20
        outcome = volley(gateway, "POST", path, count)
        let_through = outcome.count(200)
        most = most_let_through(AUTH_RATE, burst, outcome.elapsed)
        check(
            only(outcome, 200, 429)
            and burst + 1 <= let_through <= most
            and outcome.count(429) >= 1,
            f"auth, {count} at once to {name}: {let_through} let through "
            f"(the burst of {burst} and one; at most {most} in "
            f"{outcome.elapsed * 1000:.0f} ms at {AUTH_RATE} r/s), "
            f"{outcome.count(429)} x 429",
            outcome.describe(),
        )
        received += outcome.count(429)
        limited += len(outcome.limited)

    quiet()
    seconds = 4
    outcome = stream(gateway, "POST", LOGIN, seconds, connections=3, pause=0.01)
    let_through = outcome.count(200)
    most = most_let_through(AUTH_RATE, LOGIN_BURST, outcome.elapsed)
    least = least_let_through(AUTH_RATE, LOGIN_BURST, outcome.elapsed)
    check(
        only(outcome, 200, 429) and least <= let_through <= most,
        f"auth, a stream of {len(outcome.answers)} logins in {outcome.elapsed:.1f} s: "
        f"{let_through} let through, which is {AUTH_RATE} r/s "
        f"(between {least} and {most})",
        outcome.describe(),
    )
    received += outcome.count(429)
    limited += len(outcome.limited)

    # One counter for the three routes: after a volley of logins there is no
    # allowance left for a registration. Only told when the registration
    # follows closely enough for the counter not to have drained.
    told = False
    for _ in range(5):
        quiet()
        connection = gateway.connection()
        began = time.monotonic()
        logins = volley(gateway, "POST", LOGIN, LOGIN_BURST + 1)
        answer = ask(connection, "POST", REGISTER)
        took = time.monotonic() - began
        connection.close()
        received += logins.count(429) + (answer.status == 429)
        limited += len(logins.limited) + answer.is_nginx_limit()
        if took < 1 / AUTH_RATE:
            told = True
            check(
                only(logins, 200) and answer.is_nginx_limit(),
                "auth: login and registration share one counter (a registration "
                f"right after {LOGIN_BURST + 1} logins is refused)",
                f"logins {logins.describe()}, registration {answer.status} "
                f"after {took * 1000:.0f} ms",
            )
            break
    if not told:
        failed(
            "auth: could not send a registration within "
            f"{1000 / AUTH_RATE:.0f} ms of the logins, five times"
        )

    check(
        limited == received,
        f"auth: every one of the {received} refusals is nginx's own 429",
        f"{received - limited} were another 429",
    )
    logged = gateway.refusals("auth") - refused_before["auth"]
    check(
        logged == received,
        f"auth: the client received {received} refusals and nginx logged "
        f"{logged} by the auth zone",
    )
    check(
        gateway.refusals("global") == refused_before["global"],
        "auth: none of them was counted by the global zone",
    )


# --- static assets ------------------------------------------------------------------


def test_static_assets_are_not_under_the_global_limit(gateway):
    quiet()
    count = 60
    outcome = volley(gateway, "GET", "/_next/static/chunks/rate-limit-test.js", count)
    check(
        only(outcome, 200),
        f"static assets: {count} at once are all served (the global limit would "
        f"refuse all but {GLOBAL_BURST + 1}; their zone allows a burst of "
        f"{STATIC_BURST})",
        outcome.describe(),
    )


# --- the rates the suites set -----------------------------------------------------


def test_the_suite_rates(image, network, production):
    """What is refused at the production rates passes at the suites' rates."""
    quiet()
    count = 300
    outcome = sequence(production, "GET", GLOBAL_PATH, count)
    check(
        outcome.count(429) >= 1,
        f"production rates: {count} requests one after another, as fast as the "
        f"gateway answers ({outcome.elapsed / count * 1000:.1f} ms each), are "
        f"refused {outcome.count(429)} times",
        outcome.describe(),
    )
    quiet()
    outcome = sequence(production, "POST", REGISTER, 12)
    check(
        outcome.count(429) >= 1,
        "production rates: 12 registrations one after another are refused "
        f"{outcome.count(429)} times",
        outcome.describe(),
    )
    quiet()

    name = f"gw-rate-limit-{os.getpid()}"
    secret = os.environ.get("CI_GATEWAY_SECRET", "rate-limit-test-secret")
    with tempfile.NamedTemporaryFile("w", suffix=".env") as env_file:
        # In a file, so the value is in no argument list.
        env_file.write(f"GATEWAY_INTERNAL_SECRET={secret}\n")
        env_file.flush()
        docker(
            "run",
            "-d",
            "--name",
            name,
            "--network",
            network,
            "-p",
            "127.0.0.1::443",
            "--env-file",
            env_file.name,
            *(
                argument
                for setting in SETTINGS
                for argument in ("-e", f"{setting}={SUITE_RATE}")
            ),
            image,
        )
    try:
        raised = None
        for _ in range(60):
            try:
                raised = Gateway(name)
                connection = raised.connection()
                ready = ask(connection, "GET", "/health").status == 200
                connection.close()
                if ready:
                    break
            except (OSError, RuntimeError, IndexError, ValueError):
                pass  # not published, no certificate or not listening yet
            raised = None
            time.sleep(0.5)
        if raised is None:
            failed(
                f"a gateway with the rates set to {SUITE_RATE} did not start: "
                + docker("logs", name, check_exit=False)[-400:]
            )
            return
        expected = (
            f"Per-address request limits: global {SUITE_RATE} r/s, "
            f"auth {SUITE_RATE} r/s, static assets {SUITE_RATE} r/s."
        )
        check(
            expected in docker("logs", name),
            f"a gateway with the three settings at {SUITE_RATE} reports them",
        )
        # nginx counts in milliseconds, and the burst is not a setting: more
        # than burst + 1 requests in the same millisecond are refused whatever
        # the rate is. The mock answers in a third of a millisecond since
        # #776, so three registrations (burst 2) could fall in one and the
        # fourth was refused now and then (seen in CI: 59 answered and one
        # refused, in 21 ms). A suite never sends two requests in the same
        # millisecond: its stack answers in seven. The
        # two auth routes are asked at that order of pace, a hundred times the
        # production rate, and the global limit, whose burst of ten a single
        # connection cannot fill, as fast as it answers.
        for label, method, path, count, status, pause in (
            ("requests under the global limit", "GET", GLOBAL_PATH, 600, 401, 0.0),
            ("logins", "POST", LOGIN, 60, 200, SUITE_PAUSE),
            ("registrations", "POST", REGISTER, 60, 200, SUITE_PAUSE),
        ):
            outcome = sequence(raised, method, path, count, pause)
            check(
                only(outcome, status),
                f"suite rates: {count} {label} one after another "
                f"({outcome.elapsed / count * 1000:.1f} ms each) are all let through",
                outcome.describe(),
            )
        # Several requests at once, again and again, as a page of the
        # dashboard and the busiest tests send them.
        for _ in range(5):
            outcome = volley(raised, "GET", GLOBAL_PATH, GLOBAL_BURST)
            if not only(outcome, 401):
                break
        check(
            only(outcome, 401),
            f"suite rates: five volleys of {GLOBAL_BURST} at once, back to back, "
            "are let through",
            outcome.describe(),
        )
        check(
            raised.refusals("global") == 0 and raised.refusals("auth") == 0,
            "suite rates: nginx logged no refusal by any zone",
        )
    finally:
        docker("rm", "-f", name, check_exit=False)


def main(arguments):
    if len(arguments) < 2:
        print(__doc__)
        return 2
    image, network = arguments[0], arguments[1]
    container = arguments[2] if len(arguments) > 2 else "gateway-prod"

    print(f"== Per-address request limits, container {container} ({image}) ==")
    production = Gateway(container)
    test_defaults(production)
    test_early_answers_are_not_counted(production)
    test_global_zone(production)
    test_auth_zone(production)
    test_static_assets_are_not_under_the_global_limit(production)
    test_the_suite_rates(image, network, production)

    print()
    print(f"== Results: {PASSED} passed, {FAILED} failed ==")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
