"""Importing open_security_shared must not pull in optional dependencies.

The shared package has no dependency of its own, on purpose: it must not
change a service's dependency tree. A service installs it with the extras of
the modules it imports and locks what those need (#722). That only works if
importing the package does not immediately import the dependencies of
submodules the service never uses.

It did. `__init__.py` imported a module of JWT helpers at module level, which
imported `jose`. Four services import the shared package and none of them
pinned python-jose, so `import app.main` in the tools service died with:

    ModuleNotFoundError: No module named 'jose'

-- the service could not start. The names are resolved lazily now (PEP 562);
these tests fail if an eager import comes back. That module (`auth_utils`) and
the others no service imported are gone (#665), so what is left to keep
apart is FastAPI, for guardian and the sensor, which install the package
without it, and prometheus_client, which only `observability` needs.
"""

import subprocess
import sys
import textwrap

import pytest

# Third-party modules that only some submodules need. None may be imported as a
# side effect of importing the package or of using the modules that need no
# extra.
OPTIONAL = ("fastapi", "starlette", "pydantic", "prometheus_client")


def _imported_after(code: str) -> set:
    """Run `code` in a fresh interpreter, return the third-party modules loaded."""
    script = textwrap.dedent(f"""
        import json, sys
        {code}
        loaded = [m for m in {OPTIONAL!r} if m in sys.modules]
        print(json.dumps(loaded))
        """)
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    if out.returncode != 0:
        pytest.fail(f"import failed:\n{out.stderr.strip()}")
    import json

    return set(json.loads(out.stdout.strip().splitlines()[-1]))


def test_importing_the_package_pulls_in_nothing_optional():
    assert _imported_after("import open_security_shared") == set()


def test_the_modules_without_an_extra_pull_in_nothing():
    """guardian (Django) imports scopes; it must not need FastAPI for it."""
    loaded = _imported_after(
        "from open_security_shared import scopes, environment, api_docs\n"
        "        from open_security_shared import circuit_breaker"
    )
    assert loaded == set()


def test_error_helpers_do_not_pull_in_the_metrics_dependency():
    loaded = _imported_after(
        "from open_security_shared import install_error_handlers, error_body"
    )
    assert "fastapi" in loaded
    assert "prometheus_client" not in loaded


def test_observability_helpers_resolve_without_the_error_module():
    loaded = _imported_after(
        "import sys\n"
        "        from open_security_shared import install_observability\n"
        "        assert 'open_security_shared.errors' not in sys.modules"
    )
    assert "prometheus_client" in loaded


def test_lazy_names_still_resolve():
    """Laziness must not break the public API."""
    import open_security_shared as shared

    for name in shared.__all__:
        assert hasattr(shared, name), f"{name} is exported but does not resolve"


def test_unknown_attribute_still_raises_attribute_error():
    import open_security_shared as shared

    with pytest.raises(AttributeError):
        shared.definitely_not_a_real_export
