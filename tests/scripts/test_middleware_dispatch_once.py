"""No middleware of any service dispatches a request more than once.

identity's database middleware caught what a route raised and answered by
calling ``call_next`` again: a failed request was sent into the application
a second time. How far the second run got was up to the framework. A
middleware calls downstream once; an error downstream is answered, not
retried.

This reads every tracked Python file of the services and the shared package
and refuses, in any function, a call to ``call_next`` (ASGI) or
``get_response`` (Django)

- inside an ``except`` or ``finally`` clause: the retry;
- inside a loop;
- more than once, unless every call but one is the value of a ``return``
  (an early exit, as the idempotency middleware has for requests it skips).
"""

import ast
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOWNSTREAM = frozenset({"call_next", "get_response"})
_SKIPPED_PARTS = frozenset({"tests", "test", "node_modules", "migrations"})


def is_downstream_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return name in DOWNSTREAM


def problems(source: str) -> list:
    """(line, what is wrong) for each downstream call that can run twice."""
    found = []

    def walk(node, in_handler, in_loop, calls):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                inner = []
                walk(child, False, False, inner)
                not_returned = [line for line, returned in inner if not returned]
                if len(not_returned) > 1:
                    found.append((not_returned[1], "calls downstream more than once"))
                continue
            handler = in_handler or isinstance(child, ast.ExceptHandler)
            loop = in_loop or isinstance(child, (ast.For, ast.AsyncFor, ast.While))
            if isinstance(node, ast.Try) and child in node.finalbody:
                handler = True
            if is_downstream_call(child):
                if in_handler or handler:
                    found.append(
                        (
                            child.lineno,
                            "calls downstream from an except or finally clause",
                        )
                    )
                elif in_loop or loop:
                    found.append((child.lineno, "calls downstream in a loop"))
                calls.append((child.lineno, is_returned(node, child)))
            walk(child, handler, loop, calls)

    def is_returned(parent, call):
        # `return await call_next(request)` or `return call_next(request)`
        if isinstance(parent, ast.Return):
            return True
        return isinstance(parent, ast.Await) and parent in returned_awaits

    tree = ast.parse(source)
    returned_awaits = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Await)
    }
    walk(tree, False, False, [])
    return sorted(set(found))


def service_files() -> list:
    listed = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--",
            "open-security-*/**/*.py",
            "open-security-*/*.py",
        ],
        cwd=REPO,
        capture_output=True,
        check=True,
    )
    paths = [path for path in listed.stdout.decode().split("\0") if path]
    return [
        path
        for path in paths
        if not _SKIPPED_PARTS & set(path.split("/")[:-1])
        and not Path(path).name.startswith("test_")
    ]


# --- the rule ----------------------------------------------------------------


def check(body: str) -> list:
    return [what for _, what in problems(textwrap.dedent(body))]


def test_the_retry_identity_had_is_refused():
    assert (
        check("""
        async def db_session_middleware(request, call_next):
            try:
                response = await call_next(request)
            except ValueError:
                response = await call_next(request)
            return response
        """)
        == [
            "calls downstream from an except or finally clause",
            "calls downstream more than once",
        ]
    )


def test_a_retry_loop_is_refused():
    assert check("""
        async def dispatch(self, request, call_next):
            for attempt in range(3):
                try:
                    return await call_next(request)
                except ConnectionError:
                    continue
        """) == ["calls downstream in a loop"]


def test_a_django_middleware_that_retries_is_refused():
    assert check("""
        class Retry:
            def __call__(self, request):
                try:
                    return self.get_response(request)
                finally:
                    self.get_response(request)
        """) == ["calls downstream from an except or finally clause"]


def test_two_calls_on_the_same_path_are_refused():
    assert check("""
        async def dispatch(self, request, call_next):
            first = await call_next(request)
            second = await call_next(request)
            return second
        """) == ["calls downstream more than once"]


def test_one_call_is_accepted_with_its_error_handling():
    assert check("""
        async def dispatch(self, request, call_next):
            try:
                response = await call_next(request)
            except OperationalError:
                return unavailable()
            finally:
                record()
            return response
        """) == []


def test_early_exits_that_return_the_downstream_answer_are_accepted():
    # The idempotency middleware: requests it does not handle go straight on.
    assert check("""
        async def dispatch(self, request, call_next):
            if request.method != "POST":
                return await call_next(request)
            if not key(request):
                return await call_next(request)
            response = await call_next(request)
            store(response)
            return response
        """) == []


def test_each_function_is_judged_on_its_own():
    assert check("""
        async def first(request, call_next):
            return await call_next(request)

        async def second(request, call_next):
            response = await call_next(request)
            return response
        """) == []


# --- the repository ----------------------------------------------------------


def middleware_files() -> list:
    """The service files that name a downstream call at all."""
    return [
        path
        for path in service_files()
        if any(
            f"{name}(" in (REPO / path).read_text(encoding="utf-8")
            for name in DOWNSTREAM
        )
    ]


def test_the_services_have_middlewares_for_this_to_read():
    # Seven services and the shared package had one when this was written.
    assert len(middleware_files()) >= 8, middleware_files()


@pytest.mark.parametrize("path", middleware_files())
def test_no_middleware_dispatches_twice(path):
    assert problems((REPO / path).read_text(encoding="utf-8")) == [], path
