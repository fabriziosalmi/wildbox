"""setup.py declares no command it does not package (#665).

It declared ``security-sensor`` and ``ossensor`` as ``main:main``. main.py is
a file beside the package, not part of it (``find_packages()`` finds
``sensor`` only), so after ``pip install .`` both commands failed with
``ModuleNotFoundError: No module named 'main'``. They answered only in the
image, where an editable install puts /app on the path, and nothing there
ran them: the image starts ``python main.py``.

A console script, if one is ever added, has to name a module the
distribution installs.
"""

import ast
import re
import sys
from pathlib import Path

import pytest

SENSOR_ROOT = Path(__file__).resolve().parents[2]


def setup_keywords():
    tree = ast.parse((SENSOR_ROOT / "setup.py").read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "setup"
    ]
    assert len(calls) == 1
    return {keyword.arg: keyword.value for keyword in calls[0].keywords}


def console_scripts(keywords):
    entry_points = keywords.get("entry_points")
    if entry_points is None:
        return []
    return ast.literal_eval(entry_points).get("console_scripts", [])


def test_every_console_script_names_a_module_that_is_installed():
    keywords = setup_keywords()
    py_modules = (
        ast.literal_eval(keywords["py_modules"]) if "py_modules" in keywords else []
    )
    for script in console_scripts(keywords):
        module = script.split("=", 1)[1].split(":", 1)[0].strip()
        top = module.split(".", 1)[0]
        packaged = top in py_modules or (SENSOR_ROOT / top / "__init__.py").is_file()
        assert packaged, (
            f"{script!r}: {module} is not installed by setup.py (it packages "
            "the `sensor` package only), so the command fails after "
            "`pip install .` with ModuleNotFoundError."
        )


def test_the_check_sees_the_scripts_that_were_removed():
    # What setup.py declared: main.py is not a package and was not listed.
    tree = ast.parse(
        "setup(entry_points={'console_scripts': ['security-sensor=main:main']})"
    )
    keywords = {k.arg: k.value for k in tree.body[0].value.keywords}
    assert console_scripts(keywords) == ["security-sensor=main:main"]
    assert not (SENSOR_ROOT / "main" / "__init__.py").exists()
    assert (SENSOR_ROOT / "main.py").is_file()


def test_no_extra_names_a_package_the_sensor_does_not_import():
    # `windows` and `macos` named pywin32, wmi and pyobjc; the sensor reads
    # those systems' logs by running their own commands.
    assert "extras_require" not in setup_keywords()


# -- what the image installs (#777) -------------------------------------------
#
# requirements.txt is the lock the image installs, compiled from
# requirements.in, which is also setup.py's install_requires. Both named the
# test runner and the linters: the image shipped pytest, black, flake8 and
# mypy with everything they bring, and `pip install .` required them.

NOT_FOR_THE_IMAGE = {
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "black",
    "flake8",
    "mypy",
    # With the CORS layer of the local API: see test_local_api_cors.py.
    "aiohttp-cors",
}
# What comes with those and with nothing the sensor imports.
BROUGHT_BY_THEM = {
    "coverage",
    "iniconfig",
    "pluggy",
    "pygments",
    "click",
    "pathspec",
    "platformdirs",
    "pytokens",
    "mccabe",
    "pycodestyle",
    "pyflakes",
    "mypy-extensions",
    "packaging",
    "tomli",
}


def distributions(name):
    """The distributions a requirements file names, as PyPI compares them."""
    names = set()
    for line in (SENSOR_ROOT / name).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        found = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", line)
        assert found, line
        names.add(re.sub(r"[-_.]+", "-", found.group(0)).lower())
    return names


def test_the_requirements_name_what_the_sensor_runs_with_and_no_tool():
    direct = distributions("requirements.in")

    assert direct == {"aiohttp", "pyyaml", "psutil", "cryptography"}
    assert not direct & NOT_FOR_THE_IMAGE


def test_the_lock_the_image_installs_holds_no_test_runner_and_no_linter():
    locked = distributions("requirements.txt")

    # Every direct requirement, and what those need.
    assert distributions("requirements.in") <= locked
    # main: all seven, and the fourteen that came with them.
    assert sorted(locked & NOT_FOR_THE_IMAGE) == []
    assert sorted(locked & BROUGHT_BY_THEM) == []


def test_the_image_installs_that_lock_and_nothing_beside_it():
    dockerfile = (SENSOR_ROOT / "Dockerfile").read_text(encoding="utf-8")
    installs = [
        line.strip()
        for line in dockerfile.splitlines()
        if re.match(r"\s*(RUN\s+|&&\s+)?pip install", line)
    ]

    # The lock, hash-checked; then the shared package and the sensor
    # itself, from what is already in the image (--no-index).
    assert len(installs) == 3
    assert "--require-hashes" in installs[0] and "-r requirements.txt" in installs[0]
    assert all("--no-index" in line for line in installs[1:])


def test_the_unit_test_job_installs_what_the_tests_import():
    # The test runner is no longer in the lock: the job that runs these
    # tests installs it, with its plugins, on top of the lock. Every module
    # a test imports must come from one or the other.
    workflow = SENSOR_ROOT.parent / ".github" / "workflows" / "test.yml"
    if not workflow.is_file():
        pytest.skip("the workflows are not in this checkout")
    text = workflow.read_text(encoding="utf-8")
    step = text.split("- name: Install dependencies for ${{ matrix.service }}")[1]
    step = step.split("- name:")[0]
    assert "pip install -r requirements.txt" in step
    (tools,) = re.findall(r"^\s*pip install ((?:[a-z-]+==[0-9.]+ ?)+)$", step, re.M)
    installed = {tool.split("==")[0] for tool in tools.split()}
    assert installed == {"pytest", "pytest-cov", "pytest-asyncio"}
    # The sensor is one of the services of that job.
    matrix = text.split("service:")[1].split("steps:")[0]
    assert re.search(r"^\s*- sensor$", matrix, re.M)

    provided = {
        "yaml" if name == "pyyaml" else name.replace("-", "_")
        for name in distributions("requirements.txt") | installed
    }
    tests = sorted((SENSOR_ROOT / "tests").rglob("*.py"))
    imported = set()
    for path in tests:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
    # The sensor's own modules and the standard library aside.
    own = {"main", "sensor"} | {path.stem for path in tests}
    needed = imported - own - set(sys.stdlib_module_names)

    assert len(tests) > 30
    assert {"pytest", "pytest_asyncio", "yaml", "aiohttp"} <= needed
    assert needed - provided == set()
