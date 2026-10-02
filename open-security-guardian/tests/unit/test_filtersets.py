"""Every filterset a list endpoint uses must be able to build its form.

django-filter builds the form of a FilterSet lazily, on the first request that
reaches ``DjangoFilterBackend.filter_queryset``. A django-filter release that
does not support the installed Django therefore imports, passes ``manage.py
check`` and serves the schema, and only fails at request time: with Django 5.2
and django-filter 23.2 every ``ChoiceFilter`` raised ``AttributeError: 'super'
object has no attribute '_set_choices'`` and ``GET /api/v1/vulnerabilities/``
answered 500.

This walks the URLconf, takes every DRF viewset that filters with
``DjangoFilterBackend``, and builds the form of the filterset it would use --
the declared ``filterset_class`` or the one generated from
``filterset_fields``. Building the form touches no database.
"""

import pytest
from django.urls import URLPattern, URLResolver, get_resolver
from django_filters.rest_framework import DjangoFilterBackend


def _viewsets(patterns=None, seen=None):
    seen = set() if seen is None else seen
    for entry in get_resolver().url_patterns if patterns is None else patterns:
        if isinstance(entry, URLResolver):
            yield from _viewsets(entry.url_patterns, seen)
        elif isinstance(entry, URLPattern):
            cls = getattr(entry.callback, "cls", None)
            actions = getattr(entry.callback, "actions", None) or {}
            if cls is not None and "list" in actions.values() and cls not in seen:
                seen.add(cls)
                yield cls


def _filtered_viewsets():
    found = []
    for cls in _viewsets():
        if any(issubclass(b, DjangoFilterBackend) for b in cls.filter_backends):
            found.append(cls)
    return sorted(found, key=lambda c: f"{c.__module__}.{c.__qualname__}")


def _queryset_for(view_cls):
    queryset = getattr(view_cls, "queryset", None)
    if queryset is not None:
        return queryset.none()
    filterset_class = getattr(view_cls, "filterset_class", None)
    if filterset_class is not None and filterset_class._meta.model is not None:
        return filterset_class._meta.model._default_manager.none()
    serializer_class = getattr(view_cls, "serializer_class", None)
    model = getattr(getattr(serializer_class, "Meta", None), "model", None)
    if model is not None:
        return model._default_manager.none()
    return None


FILTERED = _filtered_viewsets()

# These already fail on Django 4.2 / django-filter 23.2, for reasons that have
# nothing to do with the versions: their ``filterset_fields`` name fields the
# model does not have (TypeError "'Meta.fields' must not contain non-model
# field names") or a JSONField django-filter cannot map. Their list endpoints
# answer 500 whenever DjangoFilterBackend runs. strict=True: fixing one turns
# its xfail into a failure, so it has to come off this list.
KNOWN_BROKEN = {
    "IntegrationLogViewSet",
    "NotificationChannelViewSet",
    "SyncRecordViewSet",
    "WebhookEndpointViewSet",
    "RemediationCommentViewSet",
    "RemediationStepViewSet",
    "RemediationTicketViewSet",
}


def _param(view_cls):
    marks = []
    if view_cls.__qualname__ in KNOWN_BROKEN:
        marks.append(
            pytest.mark.xfail(
                strict=True, reason="filterset_fields broken before Django 5.2"
            )
        )
    return pytest.param(view_cls, id=view_cls.__qualname__, marks=marks)


def test_there_are_filtered_viewsets():
    # Guards the parametrization below against silently collecting nothing.
    assert len(FILTERED) > 0


@pytest.mark.parametrize("view_cls", [_param(c) for c in FILTERED])
def test_filterset_form_builds(view_cls):
    queryset = _queryset_for(view_cls)
    if queryset is None:
        pytest.skip("no static queryset to derive a filterset from")
    view = view_cls()
    view.action = "list"
    filterset_class = DjangoFilterBackend().get_filterset_class(view, queryset)
    if filterset_class is None:
        pytest.skip("viewset declares no filters")
    filterset = filterset_class(data={}, queryset=queryset)
    form = filterset.form
    assert set(form.fields) == set(filterset.filters)
