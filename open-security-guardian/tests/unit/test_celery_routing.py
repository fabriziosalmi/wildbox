"""Every guardian task is routed to the queue it is meant for (#545).

The routes in guardian/celery.py were globs such as ``reporting.tasks.*``
while the tasks register as ``apps.reporting.tasks.*``: nothing matched and
every task went to ``default``. ``TASK_QUEUES`` in guardian/celery.py is now
the single list of which queue each task belongs to. These tests check it
against the tasks Celery actually registers and against the router, so a new
task that nobody gave a queue fails here instead of landing in ``default``
unnoticed, and so does a name that no longer matches its task.
"""

import shlex
from pathlib import Path

import pytest
import yaml
from guardian.celery import TASK_QUEUES, app

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
BLUE_GREEN_FILE = REPO_ROOT / "docker-compose.blue-green.yml"


def _registered():
    """guardian's own tasks, as the worker registers them."""
    app.loader.import_default_modules()
    return {name for name in app.tasks if not name.startswith("celery.")}


def _intended():
    """task name -> queue, from TASK_QUEUES; a task may be listed only once."""
    intended = {}
    for queue, names in TASK_QUEUES.items():
        for name in names:
            assert (
                name not in intended
            ), f"{name} is listed under {intended[name]} and {queue}"
            intended[name] = queue
    return intended


def _routed_queue(name):
    return app.amqp.router.route({}, name)["queue"].name


def test_every_registered_task_has_an_intended_queue():
    missing = sorted(_registered() - set(_intended()))
    assert (
        not missing
    ), f"tasks with no queue in guardian/celery.py TASK_QUEUES: {missing}"


def test_every_listed_task_is_registered():
    # A name that matches no task is a route that does nothing, which is
    # exactly what the old globs were.
    stale = sorted(set(_intended()) - _registered())
    assert not stale, f"TASK_QUEUES names tasks that do not exist: {stale}"


def test_each_task_resolves_to_its_intended_queue():
    intended = _intended()
    wrong = {
        name: (_routed_queue(name), intended.get(name))
        for name in sorted(_registered())
        if _routed_queue(name) != intended.get(name)
    }
    assert not wrong, f"task: (routed to, intended): {wrong}"


def test_no_task_is_left_on_default_by_accident():
    # The periodic sweeps and notifications are on default by decision; a
    # scanning or reporting task there would mean its route stopped matching.
    assert _routed_queue("apps.assets.tasks.scan_asset_ports") == "scanning"
    assert _routed_queue("apps.reporting.tasks.generate_report") == "reporting"
    assert (
        _routed_queue("apps.vulnerabilities.tasks.update_vulnerability_risk_scores")
        == "analytics"
    )


def test_celery_builtin_tasks_use_the_default_queue():
    builtins = sorted(name for name in app.tasks if name.startswith("celery."))
    assert builtins
    assert {name: _routed_queue(name) for name in builtins} == {
        name: "default" for name in builtins
    }


def _services(path):
    return yaml.safe_load(path.read_text())["services"]


def _argv(service):
    command = service["command"]
    return shlex.split(command) if isinstance(command, str) else list(command)


def _worker_queues(service="guardian-worker", path=COMPOSE_FILE):
    argv = _argv(_services(path)[service])
    return argv[argv.index("-Q") + 1].split(",")


@pytest.mark.skipif(not COMPOSE_FILE.exists(), reason="needs the repository checkout")
def test_the_worker_consumes_exactly_the_routed_queues():
    # A queue routed to but not consumed is a queue whose tasks never run; a
    # queue consumed but never routed to is a leftover.
    queues = _worker_queues()
    assert len(queues) == len(set(queues)), queues
    assert set(queues) == set(TASK_QUEUES), queues


@pytest.mark.skipif(
    not BLUE_GREEN_FILE.exists(), reason="needs the repository checkout"
)
@pytest.mark.parametrize("color", ["blue", "green"])
def test_each_blue_green_worker_consumes_exactly_the_routed_queues(color):
    # docker-compose.blue-green.yml had no worker at all (#550).
    queues = _worker_queues(f"guardian-worker-{color}", BLUE_GREEN_FILE)
    assert len(queues) == len(set(queues)), queues
    assert set(queues) == set(TASK_QUEUES), queues


@pytest.mark.skipif(
    not BLUE_GREEN_FILE.exists(), reason="needs the repository checkout"
)
def test_blue_green_runs_one_beat_for_both_colors():
    # Beat has no leader election: a beat per color would send every
    # periodic task twice while both colors run (#550).
    services = _services(BLUE_GREEN_FILE)
    beats = {
        name: service
        for name, service in services.items()
        if "command" in service and "beat" in _argv(service)
    }
    assert list(beats) == ["guardian-beat"], list(beats)
    beat = beats["guardian-beat"]
    # A fixed container name: compose cannot scale it to two, and changing
    # its image (the active color) replaces the one container.
    assert beat.get("container_name")
    assert beat["image"] == "wildbox-guardian:${GUARDIAN_ACTIVE_COLOR:-blue}"
    # The image it may run is exactly one the colors build.
    built = {services[f"guardian-{c}"]["image"] for c in ("blue", "green")}
    assert built == {"wildbox-guardian:blue", "wildbox-guardian:green"}
