"""Importing open_security_shared must not pull in optional dependencies.

Services install the shared package with `pip install --no-deps`, on purpose:
the shared package must not silently change a service's dependency tree. That
only works if importing it does not immediately import the dependencies of
submodules the service never uses.

It did. `__init__.py` did `from .auth_utils import ...` at module level, and
auth_utils does `from jose import JWTError, jwt`. Four services import the
shared package and none of them pin python-jose, so `import app.main` in the
tools service died with:

    ModuleNotFoundError: No module named 'jose'

-- the service could not start. The names are resolved lazily now (PEP 562);
these tests fail if an eager import comes back.
"""

import subprocess
import sys
import textwrap

import pytest

# Third-party modules that only some submodules need. None may be imported as a
# side effect of importing the package or of using the light-weight helpers.
OPTIONAL = ("jose", "opentelemetry", "redis", "sqlalchemy", "prometheus_client")


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


def test_error_helpers_do_not_pull_in_auth_dependencies():
    loaded = _imported_after(
        "from open_security_shared import install_error_handlers, error_body"
    )
    assert "jose" not in loaded


def test_observability_helpers_do_not_pull_in_auth_dependencies():
    loaded = _imported_after(
        "from open_security_shared import install_observability, outcome_counter"
    )
    assert "jose" not in loaded


def test_lazy_names_still_resolve():
    """Laziness must not break the public API."""
    import open_security_shared as shared

    for name in shared.__all__:
        assert hasattr(shared, name), f"{name} is exported but does not resolve"


def test_unknown_attribute_still_raises_attribute_error():
    import open_security_shared as shared

    with pytest.raises(AttributeError):
        shared.definitely_not_a_real_export
