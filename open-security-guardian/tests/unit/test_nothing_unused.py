"""No serializer nothing uses, no view nothing routes (#724).

Three serializers of the scanners app described answers and requests the
API does not have: ``BulkScanActionSerializer`` (start, pause, cancel and
delete scans in bulk), ``ScannerHealthSerializer`` (``response_time_ms`` of a
scanner guardian never contacts) and ``ScanResultSummarySerializer``. And
``SystemInfoView`` was a view no URL led to. Code like this reads as a
feature to whoever opens the file, and is the first half of the next
placeholder: #644 removed twenty actions that answered success and did
nothing, several of them built on a serializer that was already there.

So: every serializer class is used somewhere other than where it is
defined, and every view class is routed.
"""

import importlib
import inspect
import re
from pathlib import Path

from django.urls import URLPattern, URLResolver, get_resolver
from django.views import View
from rest_framework import serializers

APPS_DIR = Path(__file__).resolve().parents[2] / "apps"
_GUARDIAN_APPS = (
    "assets",
    "vulnerabilities",
    "scanners",
    "remediation",
    "compliance",
    "integrations",
    "reporting",
)


def _sources():
    return {
        path: path.read_text(encoding="utf-8")
        for path in APPS_DIR.rglob("*.py")
        if "migrations" not in path.parts
    }


def _defined(module_name, base):
    module = importlib.import_module(module_name)
    return [
        value
        for value in vars(module).values()
        if inspect.isclass(value)
        and issubclass(value, base)
        and value.__module__ == module.__name__
    ]


def test_every_serializer_is_used():
    sources = _sources()
    classes = [
        cls
        for label in _GUARDIAN_APPS
        for cls in _defined(f"apps.{label}.serializers", serializers.BaseSerializer)
    ]
    assert len(classes) > 45
    unused = []
    for cls in classes:
        name = re.compile(rf"\b{cls.__name__}\b")
        definition = re.compile(rf"^class {cls.__name__}\(", re.M)
        uses = sum(
            len(name.findall(text)) - len(definition.findall(text))
            for text in sources.values()
        )
        # Named in an import and nowhere else is not a use either.
        imports = sum(
            len(re.findall(rf"^\s+{cls.__name__},?$", text, re.M))
            + len(re.findall(rf"^from .* import .*\b{cls.__name__}\b", text, re.M))
            for text in sources.values()
        )
        if uses - imports <= 0:
            unused.append(f"{cls.__module__}.{cls.__name__}")
    assert not unused, (
        f"{unused} are defined and used by nothing: remove them, or route "
        "what they are for."
    )


def _routed_views(patterns=None):
    for entry in get_resolver().url_patterns if patterns is None else patterns:
        if isinstance(entry, URLResolver):
            yield from _routed_views(entry.url_patterns)
        elif isinstance(entry, URLPattern):
            view = getattr(entry.callback, "cls", None) or getattr(
                entry.callback, "view_class", None
            )
            if view is not None:
                yield view


def test_every_view_is_routed():
    routed = set(_routed_views())
    modules = [f"apps.{label}.views" for label in _GUARDIAN_APPS]
    modules += ["apps.core.views", "apps.core.internal_views"]
    views = [cls for module in modules for cls in _defined(module, View)]
    assert len(views) > 40
    unrouted = sorted(
        f"{cls.__module__}.{cls.__name__}" for cls in views if cls not in routed
    )
    assert not unrouted, f"{unrouted} are views no URL leads to."
