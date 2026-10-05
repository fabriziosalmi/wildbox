"""Tests for check_shared_dependencies.py, the guard on what the shared package needs.

open-security-shared declared five dependencies for the whole package and
every image installed it with ``--no-deps``: ``pip check`` failed in seven
images of eight and nothing ran it (#722). The package now has no core
dependency and one extra per group of modules; a Dockerfile names the extras
of the modules its service imports and lets pip resolve them offline against
the lock. These feed the checker modules, Dockerfiles and locks as text, run
it on small trees, then on the repository itself.
"""

import importlib.util
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_shared_dependencies.py"
spec = importlib.util.spec_from_file_location("check_shared_dependencies", SCRIPT)
csd = importlib.util.module_from_spec(spec)
# dataclasses resolves string annotations through sys.modules.
sys.modules[spec.name] = csd
spec.loader.exec_module(csd)


def shared(
    modules: dict,
    extras: dict,
    module_extras: dict,
    core: tuple = (),
    exports: dict | None = None,
):
    return csd.Shared(
        core=tuple(Requirement(text) for text in core),
        extras={
            name: tuple(Requirement(text) for text in requirements)
            for name, requirements in extras.items()
        },
        module_extras={name: tuple(value) for name, value in module_extras.items()},
        modules={name: textwrap.dedent(source) for name, source in modules.items()},
        exports=exports or {},
    )


EXTRAS = {
    "fastapi": ["fastapi>=0.110", "pydantic>=2"],
    "auth": ["fastapi>=0.110", "passlib[bcrypt]>=1.7", "PyJWT>=2.10"],
    "metrics": ["fastapi>=0.110", "prometheus-client>=0.20"],
}
MODULES = {
    "api_docs": "import os\n",
    "errors": "from fastapi import FastAPI\nfrom starlette.exceptions import HTTPException\n",
    "auth_utils": "import jwt\nfrom fastapi import Header\nfrom passlib.context import CryptContext\n",
    "observability": """
        from fastapi import FastAPI
        try:
            from prometheus_client import Counter
        except ImportError:
            Counter = None
        """,
    "tenancy": "from .errors import thing\n",
}
MODULE_EXTRAS = {
    "api_docs": [],
    "errors": ["fastapi"],
    "auth_utils": ["auth"],
    "observability": ["metrics"],
    "tenancy": ["fastapi"],
}


def good_shared(**changes):
    values = {"modules": MODULES, "extras": EXTRAS, "module_extras": MODULE_EXTRAS}
    values.update(changes)
    return shared(**values)


# --- What a module of the package imports ------------------------------------


def test_module_level_imports_count_whatever_the_form():
    third_party, siblings = csd.module_imports(textwrap.dedent("""
        from __future__ import annotations
        import json
        import jwt
        import redis.asyncio as redis
        from fastapi.responses import JSONResponse
        from .gateway_auth import GatewayUser
        from open_security_shared.errors import error_body
        """))
    assert third_party == {"jwt", "redis.asyncio", "fastapi.responses"}
    assert siblings == {"gateway_auth", "errors"}


def test_a_guarded_import_counts_because_the_extra_is_what_makes_it_real():
    third_party, _ = csd.module_imports(textwrap.dedent("""
        try:
            from prometheus_client import Counter
        except ImportError:
            Counter = None
        """))
    assert third_party == {"prometheus_client"}


def test_imports_in_functions_and_for_type_checkers_do_not_count():
    third_party, siblings = csd.module_imports(textwrap.dedent("""
        from typing import TYPE_CHECKING

        if TYPE_CHECKING:
            from sqlalchemy import Table
            from .auth_utils import AuthConfig

        def late():
            from opentelemetry import trace
            from .tracing import setup
        """))
    assert third_party == set() and siblings == set()


@pytest.mark.parametrize(
    "module, distribution",
    [
        ("fastapi.responses", "fastapi"),
        ("starlette.middleware.base", "fastapi"),
        ("jwt", "pyjwt"),
        ("prometheus_client", "prometheus-client"),
        ("opentelemetry", "opentelemetry-api"),
        ("opentelemetry.propagate", "opentelemetry-api"),
        ("opentelemetry.sdk.trace.export", "opentelemetry-sdk"),
        ("opentelemetry.propagators.b3", "opentelemetry-propagator-b3"),
        (
            "opentelemetry.exporter.otlp.proto.http.trace_exporter",
            "opentelemetry-exporter-otlp-proto-http",
        ),
        ("numpy", None),
    ],
)
def test_the_distribution_of_an_import_is_the_longest_prefix_known(
    module, distribution
):
    assert csd.provider(module) == distribution


# --- The module table against the modules ------------------------------------


def test_modules_that_import_what_their_extras_provide_pass():
    assert csd.check_modules(good_shared()) == []


def test_an_import_the_extras_do_not_provide_fails():
    # The defect in one module: observability asking for fastapi only.
    table = {**MODULE_EXTRAS, "observability": ["fastapi"]}
    problems = csd.check_modules(good_shared(module_extras=table))
    assert len(problems) == 2
    assert "extra [metrics]: needed by no module" in problems[0]
    assert "module [observability]" in problems[1]
    assert "prometheus_client (prometheus-client)" in problems[1]


def test_a_module_with_no_extra_must_import_no_third_party_package():
    modules = {**MODULES, "api_docs": "from pydantic import BaseModel\n"}
    problems = csd.check_modules(good_shared(modules=modules))
    assert len(problems) == 1 and "module [api_docs]" in problems[0]
    assert "its extras (none)" in problems[0]


def test_a_core_dependency_provides_for_every_module():
    modules = {**MODULES, "api_docs": "from pydantic import BaseModel\n"}
    assert csd.check_modules(good_shared(modules=modules, core=("pydantic>=2",))) == []


def test_a_module_missing_from_the_table_fails():
    table = {k: v for k, v in MODULE_EXTRAS.items() if k != "errors"}
    problems = csd.check_modules(good_shared(module_extras=table))
    assert any("module [errors]: not listed" in problem for problem in problems)


def test_a_table_entry_for_a_module_that_is_gone_fails():
    table = {**MODULE_EXTRAS, "removed": []}
    problems = csd.check_modules(good_shared(module_extras=table))
    assert len(problems) == 1 and "no such module" in problems[0]


def test_an_extra_that_is_not_defined_fails():
    table = {**MODULE_EXTRAS, "api_docs": ["docs"]}
    problems = csd.check_modules(good_shared(module_extras=table))
    assert len(problems) == 1 and "the extra 'docs'" in problems[0]


def test_an_extra_no_module_needs_fails():
    extras = {**EXTRAS, "events": ["redis>=5"]}
    problems = csd.check_modules(good_shared(extras=extras))
    assert len(problems) == 1
    assert "extra [events]: needed by no module" in problems[0]


def test_an_import_of_an_unknown_package_fails():
    modules = {**MODULES, "errors": "import fastapi\nimport numpy\n"}
    problems = csd.check_modules(good_shared(modules=modules))
    assert len(problems) == 1 and "maps to no distribution" in problems[0]


def test_a_module_needs_the_extras_of_the_sibling_it_imports():
    table = {**MODULE_EXTRAS, "tenancy": []}
    problems = csd.check_modules(good_shared(module_extras=table))
    assert len(problems) == 1
    assert "module [tenancy]: imports errors, which needs fastapi" in problems[0]


# --- What a service imports --------------------------------------------------


def test_a_service_import_is_found_in_each_of_its_forms():
    package = good_shared(exports={"install_error_handlers": "errors"})
    modules, unknown = csd.service_imports(
        textwrap.dedent("""
            import open_security_shared
            import open_security_shared.api_docs
            from open_security_shared.observability import install_observability
            from open_security_shared import install_error_handlers
            from open_security_shared import tenancy as scoping

            def late():
                from open_security_shared.auth_utils import verify_password
            """),
        package,
    )
    assert modules == {"api_docs", "observability", "errors", "tenancy", "auth_utils"}
    assert unknown == []


def test_a_name_the_package_does_not_define_is_reported():
    _, unknown = csd.service_imports(
        "from open_security_shared import nothing\n"
        "from open_security_shared.gone import thing\n",
        good_shared(),
    )
    assert unknown == ["nothing", "gone"]


@pytest.mark.parametrize(
    "path, counted",
    [
        ("open-security-data/app/api/main.py", True),
        ("open-security-guardian/apps/core/views.py", True),
        ("open-security-data/tests/unit/test_auth.py", False),
        ("open-security-data/tests/unit/helpers.py", False),
        ("open-security-data/app/test_thing.py", False),
        ("open-security-data/conftest.py", False),
        ("open-security-data/README.md", False),
    ],
)
def test_only_the_code_that_runs_in_the_image_counts(path, counted):
    assert csd.is_service_code(path) is counted


# --- How a Dockerfile installs the package -----------------------------------

LOCKED = "RUN pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements.txt\n"


def dockerfile(install: str, before: str = LOCKED) -> str:
    return (
        "FROM python:3.11-slim@sha256:"
        + "0" * 64
        + "\n"
        + before
        + "COPY --from=shared . /tmp/open-security-shared\n"
        + textwrap.dedent(install)
    )


GOOD_INSTALL = """\
    RUN pip install --no-cache-dir --no-index --no-build-isolation \\
            "/tmp/open-security-shared[fastapi,metrics]" \\
        && pip check
    """


def test_the_install_is_read_with_its_extras_and_its_lock():
    install = csd.find_install(dockerfile(GOOD_INSTALL))
    assert install.extras == {"fastapi", "metrics"}
    assert install.no_deps is False and install.checked is True
    assert install.locks == ("requirements.txt",)
    assert install.line == 4


def test_an_install_without_extras_has_none():
    install = csd.find_install(
        dockerfile(
            "RUN pip install --no-index --no-build-isolation /tmp/open-security-shared"
            " && python -m pip check\n"
        )
    )
    assert install.extras == frozenset() and install.checked is True


def test_no_deps_is_seen():
    install = csd.find_install(
        dockerfile(
            "RUN pip install --no-index --no-deps /tmp/open-security-shared && pip check\n"
        )
    )
    assert install.no_deps is True


def test_pip_check_counts_only_after_the_install():
    before = csd.find_install(
        dockerfile(
            "RUN pip check && pip install --no-index '/tmp/open-security-shared[fastapi]'\n"
        )
    )
    later = csd.find_install(
        dockerfile(
            "RUN pip install --no-index '/tmp/open-security-shared[fastapi]'\n"
            "COPY . .\n"
            "RUN pip install --no-index --no-deps -e . && pip check\n"
        )
    )
    assert before.checked is False
    assert later.checked is True


def test_the_lock_of_a_builder_stage_is_the_lock():
    # cspm installs its lock under a prefix in a builder stage and copies it.
    text = (
        "FROM python:3.11 AS builder\n"
        "RUN pip install --require-hashes --no-build-isolation --prefix=/install "
        "-r requirements.txt\n"
        "FROM python:3.11\n"
        "COPY --from=builder /install /usr/local\n"
        "RUN pip install --no-index '/tmp/open-security-shared[fastapi]' && pip check\n"
    )
    assert csd.find_install(text).locks == ("requirements.txt",)


def test_a_dockerfile_that_does_not_install_the_package_has_no_install():
    assert csd.find_install("FROM node:24\nRUN npm ci\n") is None
    assert csd.find_install(dockerfile("RUN pip install --no-index -e .\n")) is None


# --- A lock against the requirements -----------------------------------------

LOCK = textwrap.dedent("""\
    # This file was autogenerated by uv
    fastapi==0.141.1 \\
        --hash=sha256:aaaa
        # via -r requirements.in
    prometheus-client==0.26.0 \\
        --hash=sha256:bbbb
    pydantic==2.10.3 \\
        --hash=sha256:cccc
    PyJWT==2.15.1 \\
        --hash=sha256:dddd
    """)


def requirements(*texts: str) -> list:
    return [Requirement(text) for text in texts]


def test_a_lock_is_read_by_canonical_name():
    assert csd.read_lock(LOCK) == {
        "fastapi": "0.141.1",
        "prometheus-client": "0.26.0",
        "pydantic": "2.10.3",
        "pyjwt": "2.15.1",
    }


def test_a_lock_that_meets_every_requirement_passes():
    wanted = requirements("fastapi>=0.110", "PyJWT>=2.10", "prometheus_client>=0.20")
    assert csd.lock_problems(wanted, csd.read_lock(LOCK), "requirements.txt") == []


def test_a_pin_below_the_floor_fails():
    # cspm, data and guardian: prometheus-client 0.19.0 against >=0.20.
    pins = csd.read_lock(
        LOCK.replace("prometheus-client==0.26.0", "prometheus-client==0.19.0")
    )
    problems = csd.lock_problems(
        requirements("prometheus-client>=0.20"), pins, "requirements.txt"
    )
    assert [name for name, _ in problems] == ["prometheus-client"]
    assert (
        "pins prometheus-client==0.19.0, outside prometheus-client>=0.20"
        in problems[0][1]
    )


def test_a_requirement_the_lock_does_not_pin_fails():
    problems = csd.lock_problems(
        requirements("passlib[bcrypt]>=1.7"), csd.read_lock(LOCK), "requirements.txt"
    )
    assert [name for name, _ in problems] == ["passlib"]
    assert "is not pinned in requirements.txt" in problems[0][1]


def test_requirements_of_several_extras_are_listed_once():
    package = good_shared()
    names = [str(r) for r in package.requirements({"fastapi", "metrics"})]
    assert names == ["fastapi>=0.110", "pydantic>=2", "prometheus-client>=0.20"]


def test_a_requirement_for_another_platform_is_not_asked_of_the_images():
    package = good_shared(core=("pywin32>=300; sys_platform == 'win32'",))
    assert [str(r) for r in package.requirements(())] == []


# --- A whole tree ------------------------------------------------------------

PYPROJECT = textwrap.dedent("""\
    [project]
    name = "open-security-shared"
    version = "1.0.0"
    dependencies = []

    [project.optional-dependencies]
    fastapi = ["fastapi>=0.110", "pydantic>=2"]
    auth = ["fastapi>=0.110", "passlib[bcrypt]>=1.7", "PyJWT>=2.10"]
    metrics = ["fastapi>=0.110", "prometheus-client>=0.20"]

    [tool.wildbox.module-extras]
    api_docs = []
    errors = ["fastapi"]
    auth_utils = ["auth"]
    observability = ["metrics"]
    """)
INIT = '_EXPORTS = {"install_error_handlers": "errors"}\n'
MAIN = textwrap.dedent("""\
    from open_security_shared.api_docs import api_docs_urls
    from open_security_shared import install_error_handlers
    from open_security_shared.observability import install_observability
    """)
SERVICE = "open-security-data"


def tree(**changes) -> dict:
    """A package with four modules and one FastAPI service that uses three."""
    files = {
        "open-security-shared/pyproject.toml": PYPROJECT,
        "open-security-shared/__init__.py": INIT,
        "open-security-shared/api_docs.py": MODULES["api_docs"],
        "open-security-shared/errors.py": MODULES["errors"],
        "open-security-shared/auth_utils.py": MODULES["auth_utils"],
        "open-security-shared/observability.py": textwrap.dedent(
            MODULES["observability"]
        ),
        f"{SERVICE}/Dockerfile": dockerfile(GOOD_INSTALL),
        f"{SERVICE}/requirements.txt": LOCK,
        f"{SERVICE}/app/main.py": MAIN,
    }
    files.update(changes)
    return files


def run(root: Path, files: dict) -> subprocess.CompletedProcess:
    for name, text in files.items():
        if text is None:
            continue
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_consistent_tree_passes(tmp_path):
    result = run(tmp_path, tree())
    assert result.returncode == 0, result.stderr
    assert "4 shared module(s)" in result.stdout and "1 image(s)" in result.stdout


def test_an_install_with_fewer_extras_than_the_imports_need_fails(tmp_path):
    install = GOOD_INSTALL.replace("[fastapi,metrics]", "[fastapi]")
    result = run(tmp_path, tree(**{f"{SERVICE}/Dockerfile": dockerfile(install)}))
    assert result.returncode == 1
    assert "extras [open-security-data]" in result.stderr
    assert "with [fastapi]; the service needs [fastapi,metrics]" in result.stderr


def test_an_install_with_more_extras_than_the_imports_need_fails(tmp_path):
    install = GOOD_INSTALL.replace("[fastapi,metrics]", "[auth,fastapi,metrics]")
    lock = LOCK + "passlib==1.7.4 \\\n    --hash=sha256:eeee\n"
    result = run(
        tmp_path,
        tree(
            **{
                f"{SERVICE}/Dockerfile": dockerfile(install),
                f"{SERVICE}/requirements.txt": lock,
            }
        ),
    )
    assert result.returncode == 1
    assert (
        "with [auth,fastapi,metrics]; the service needs [fastapi,metrics]"
        in result.stderr
    )


def test_a_new_import_asks_for_its_extra(tmp_path):
    # The service starts using auth_utils: the Dockerfile and the lock must follow.
    main = MAIN + "from open_security_shared.auth_utils import verify_password\n"
    result = run(tmp_path, tree(**{f"{SERVICE}/app/main.py": main}))
    assert result.returncode == 1
    assert "the service needs [auth,fastapi,metrics]" in result.stderr
    assert "lock [passlib]: passlib[bcrypt]>=1.7 is not pinned" in result.stderr


def test_an_import_in_a_test_asks_for_nothing(tmp_path):
    test = "from open_security_shared.auth_utils import verify_password\n"
    result = run(tmp_path, tree(**{f"{SERVICE}/tests/unit/test_auth.py": test}))
    assert result.returncode == 0, result.stderr


def test_an_install_with_no_deps_fails(tmp_path):
    install = GOOD_INSTALL.replace("--no-index", "--no-index --no-deps")
    result = run(tmp_path, tree(**{f"{SERVICE}/Dockerfile": dockerfile(install)}))
    assert result.returncode == 1
    assert "install [--no-deps]" in result.stderr


def test_an_install_without_pip_check_fails(tmp_path):
    install = GOOD_INSTALL.replace(" \\\n        && pip check", "")
    assert "pip check" not in install
    result = run(tmp_path, tree(**{f"{SERVICE}/Dockerfile": dockerfile(install)}))
    assert result.returncode == 1
    assert "install [pip check]" in result.stderr


def test_a_lock_below_the_floor_of_the_package_fails(tmp_path):
    lock = LOCK.replace("prometheus-client==0.26.0", "prometheus-client==0.19.0")
    result = run(tmp_path, tree(**{f"{SERVICE}/requirements.txt": lock}))
    assert result.returncode == 1
    assert "lock [prometheus-client]" in result.stderr
    assert (
        "open-security-data/requirements.txt pins prometheus-client==0.19.0"
        in result.stderr
    )


def test_a_lock_without_a_requirement_of_the_extras_fails(tmp_path):
    lock = LOCK.replace("pydantic==2.10.3", "pydantic-core==2.27.1")
    result = run(tmp_path, tree(**{f"{SERVICE}/requirements.txt": lock}))
    assert result.returncode == 1
    assert "lock [pydantic]: pydantic>=2 is not pinned" in result.stderr


def test_a_service_that_imports_the_package_must_install_it(tmp_path):
    result = run(
        tmp_path,
        tree(
            **{
                f"{SERVICE}/Dockerfile.dev": "FROM python:3.11\n" + LOCKED,
            }
        ),
    )
    assert result.returncode == 1
    assert (
        "open-security-data/Dockerfile.dev: install [open-security-data]"
        in result.stderr
    )


def test_a_service_that_imports_nothing_installs_no_extra(tmp_path):
    # Guardian is Django, the sensor aiohttp: the package without extras.
    plain = (
        "RUN pip install --no-cache-dir --no-index --no-build-isolation "
        "/tmp/open-security-shared \\\n    && pip check\n"
    )
    django = {
        "open-security-guardian/Dockerfile": dockerfile(plain),
        "open-security-guardian/requirements.txt": "django==5.2.17 \\\n    --hash=sha256:ffff\n",
        "open-security-guardian/apps/core/views.py": "import django\n",
    }
    assert run(tmp_path / "ok", tree(**django)).returncode == 0

    django["open-security-guardian/Dockerfile"] = dockerfile(
        plain.replace("open-security-shared ", "open-security-shared[fastapi] ")
    )
    result = run(tmp_path / "extra", tree(**django))
    assert result.returncode == 1
    assert "with [fastapi]; the service needs no extra" in result.stderr
    assert "lock [fastapi]" not in result.stderr  # asked of what it needs: nothing


def test_an_unknown_export_fails(tmp_path):
    main = MAIN + "from open_security_shared import install_everything\n"
    result = run(tmp_path, tree(**{f"{SERVICE}/app/main.py": main}))
    assert result.returncode == 1
    assert "import [install_everything]" in result.stderr


def test_a_module_whose_import_no_extra_provides_fails_the_tree(tmp_path):
    pyproject = PYPROJECT.replace(', "prometheus-client>=0.20"', "")
    result = run(tmp_path, tree(**{"open-security-shared/pyproject.toml": pyproject}))
    assert result.returncode == 1
    assert "module [observability]: imports prometheus_client" in result.stderr


def test_a_tree_where_nothing_installs_the_package_fails(tmp_path):
    result = run(
        tmp_path, tree(**{f"{SERVICE}/Dockerfile": None, f"{SERVICE}/app/main.py": ""})
    )
    assert result.returncode == 1
    assert "would pass on anything" in result.stderr


# --- The repository ----------------------------------------------------------

FASTAPI_SERVICES = ("agents", "cspm", "data", "identity", "responder", "tools")


def repository_install(name: str):
    path = REPO / f"open-security-{name}" / "Dockerfile"
    return csd.find_install(path.read_text(encoding="utf-8"))


def test_the_repository_passes():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "9 image(s)" in result.stdout


def test_the_package_has_no_core_dependency():
    # Guardian and the sensor install it and are not FastAPI services.
    document = tomllib.loads(
        (REPO / "open-security-shared" / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert document["project"]["dependencies"] == []
    assert set(document["project"]["optional-dependencies"]) == {
        "fastapi",
        "auth",
        "metrics",
        "events",
        "tracing",
    }


@pytest.mark.parametrize("name", FASTAPI_SERVICES)
def test_a_fastapi_service_installs_the_fastapi_and_metrics_extras(name):
    install = repository_install(name)
    assert install.extras == {"fastapi", "metrics"}
    assert install.no_deps is False and install.checked is True


@pytest.mark.parametrize("name", ("guardian", "sensor"))
def test_guardian_and_the_sensor_install_no_extra(name):
    install = repository_install(name)
    assert install.extras == frozenset()
    assert install.no_deps is False and install.checked is True
    pins = csd.read_lock(
        (REPO / f"open-security-{name}" / "requirements.txt").read_text(
            encoding="utf-8"
        )
    )
    assert "fastapi" not in pins  # and nothing makes them lock it


def test_every_lock_meets_every_floor_of_the_package():
    # A floor binds the services that use the extra; a lock that pins the
    # package for another reason (guardian serves its own /metrics) is held
    # to it too, so the platform runs one range of each shared dependency.
    package = csd.load_shared(REPO)
    floors = {
        csd.canonicalize_name(requirement.name): requirement
        for extra in ("fastapi", "auth", "metrics")
        for requirement in package.extras[extra]
    }
    locks = sorted(REPO.glob("open-security-*/requirements.txt"))
    assert len(locks) == 8
    for lock in locks:
        pins = csd.read_lock(lock.read_text(encoding="utf-8"))
        present = [floors[name] for name in floors if name in pins]
        assert csd.lock_problems(present, pins, str(lock)) == [], lock


def test_the_ci_jobs_run_the_check_and_build_every_image():
    workflows = REPO / ".github" / "workflows"
    integrity = (workflows / "pr-validation.yml").read_text(encoding="utf-8")
    assert "scripts/check_shared_dependencies.py" in integrity
    # The build is the check on the real environment: every image that
    # installs the package is built on a pull request, the sensor included.
    validation = (workflows / "docker-build-validation.yml").read_text(encoding="utf-8")
    for name in (*FASTAPI_SERVICES, "guardian", "sensor"):
        assert f"          - {name}\n" in validation, name
