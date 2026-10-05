"""Team isolation for guardian's data (#642).

guardian keeps the data of every team in one database. Each tenant-owned
row belongs to the team that created it; the gateway names the caller's team
in ``X-Wildbox-Team-ID`` (GatewayAuthMiddleware puts it on
``request.gateway_user.team_id``) and a request reads and writes only the
rows of that team. Everything that decides which rows a team may touch is in
this module, so that it is implemented once:

* every model a viewset serves declares how its team is found,
  ``TEAM_LOOKUP``: ``"team_id"`` for a model that stores the team itself, or
  a path through a required foreign key for a model that belongs to another
  row (``AssetPort.TEAM_LOOKUP = "asset__team_id"``). A child row has no team
  of its own to get wrong: it is the team of its parent, whoever created it
  (an API call, a Celery task, a signal);
* ``TEAM_GLOBAL_ROWS = True`` marks shared reference data (compliance
  frameworks and their controls, vulnerability templates): rows without a
  team are read by every team and written by none through the API;
* ``TeamScopedViewSetMixin`` narrows every viewset's queryset to the
  caller's team, so a row of another team answers 404, as a row that does not
  exist does;
* ``TeamScopedModelSerializer`` stamps the caller's team on the rows it
  creates (never a ``team_id`` from the request body) and narrows every
  foreign key it accepts to the rows the caller may reference, so an id of
  another team is refused as an id that does not exist.

Rows without a team on a model that is not shared reference data are the
rows written before guardian kept a team (0.8.x and earlier). No team can
reach them through the API until an operator assigns them with
``manage.py assign_guardian_team``; Celery work that belongs to such a row
(a discovery rule, a report schedule, an alert rule) sees the other rows
without a team and nothing else.
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db.models import Q
from django.utils import timezone
from django_filters import ModelChoiceFilter, ModelMultipleChoiceFilter
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import SAFE_METHODS

TEAM_FIELD = "team_id"

# auth.User rows are the gateway's identity users, mirrored on first sight
# (apps.core.gateway_middleware). A user is reachable by a team while they
# are one of its current members: they have made a request as a member of
# it, recently enough, and identity has not said they left
# (apps.core.models.TeamMembership, ``current_memberships`` below).
USER_TEAM_LOOKUP = "guardian_team_memberships__team_id"


def team_lookup(model):
    """The lookup from ``model`` to its team, or None if it has none."""
    if model is get_user_model():
        return USER_TEAM_LOOKUP
    return getattr(model, "TEAM_LOOKUP", None)


def membership_cutoff(now=None):
    """The instant before which a membership row no longer counts (#676)."""
    return (now or timezone.now()) - settings.TEAM_MEMBERSHIP_MAX_AGE


def current_memberships(team_id=None, now=None):
    """The membership rows guardian still trusts, of one team or of all.

    A row says that the gateway authenticated a user in a team at
    ``last_seen``. It is trusted for settings.TEAM_MEMBERSHIP_MAX_AGE and no
    longer: identity owns memberships, and a user it removed from a team can
    no longer make the requests that refresh the row. So a row guardian was
    never told to delete -- the notice was lost, or the member left before
    there was one -- expires instead of making an ex-member one of the
    team's users for good. Every decision about who a team's users are goes
    through here.
    """
    from apps.core.models import TeamMembership

    rows = TeamMembership.objects.filter(last_seen__gte=membership_cutoff(now))
    if team_id is not None:
        rows = rows.filter(team_id=normalize_team_id(team_id))
    return rows


def is_current_member(user, team_id):
    """True if ``user`` is, as far as guardian may trust, in ``team_id`` now."""
    if user is None or team_id is None:
        return False
    return current_memberships(team_id).filter(user_id=user.pk).exists()


def has_global_rows(model):
    """True if rows of ``model`` without a team are shared reference data."""
    return bool(getattr(model, "TEAM_GLOBAL_ROWS", False))


def owner_field(model):
    """The foreign key a derived model takes its team from, else None.

    ``"asset"`` for ``TEAM_LOOKUP = "asset__team_id"``. A request may only
    point that key at a row its own team owns: a vulnerability can reference
    a shared compliance control, but it cannot be filed under a shared
    framework, which would make it shared too.
    """
    lookup = team_lookup(model)
    if not lookup or lookup == TEAM_FIELD or "__" not in lookup:
        return None
    return lookup.split("__", 1)[0]


def normalize_team_id(team_id):
    """A team id as a UUID, or None for the rows without a team."""
    if team_id is None or team_id == "":
        return None
    if isinstance(team_id, uuid.UUID):
        return team_id
    return uuid.UUID(str(team_id))


def team_q(model, team_id, *, writable=False):
    """The ``Q`` that selects the rows of ``model`` a team may use.

    ``team_id`` None selects the rows without a team: the legacy rows, which
    the background work of a legacy row runs against. ``writable`` leaves
    out shared reference rows, which a team reads and never changes.
    """
    lookup = team_lookup(model)
    if lookup is None:
        raise ImproperlyConfigured(
            f"{model.__name__} declares no TEAM_LOOKUP: guardian cannot tell "
            "which team its rows belong to (#642)."
        )
    team_id = normalize_team_id(team_id)
    if team_id is None:
        return Q(**{f"{lookup}__isnull": True})
    if model is get_user_model():
        # A user of the team is one with a membership row of this team that
        # still counts. By primary key, not by a join on the two conditions:
        # a join lets "a row of this team" and "a row that still counts" be
        # two different rows once a caller chains filters, and a user with a
        # stale row here and a fresh one elsewhere would pass.
        return Q(pk__in=current_memberships(team_id).values("user_id"))
    condition = Q(**{lookup: team_id})
    if has_global_rows(model) and not writable:
        condition |= Q(**{f"{lookup}__isnull": True})
    return condition


def scope_to_team(queryset, team_id, *, writable=False):
    """``queryset`` narrowed to the rows of ``team_id`` (see ``team_q``)."""
    return queryset.filter(team_q(queryset.model, team_id, writable=writable))


def request_team_id(request):
    """The caller's team, from the gateway headers; refuse a request without."""
    gateway_user = getattr(request, "gateway_user", None)
    if gateway_user is None:
        # DRF wraps the Django request; the middleware set it on that one.
        gateway_user = getattr(getattr(request, "_request", None), "gateway_user", None)
    team_id = getattr(gateway_user, "team_id", None)
    if not team_id:
        raise PermissionDenied("This request names no team.")
    return normalize_team_id(team_id)


def context_team_id(context):
    """The team a serializer works for: its request's, or one given by a task."""
    if "team_id" in context:
        return normalize_team_id(context["team_id"])
    request = context.get("request")
    if request is None:
        return None
    return request_team_id(request)


class CurrentTeamDefault:
    """The caller's team, as the value of a serializer's hidden ``team_id``."""

    requires_context = True

    def __call__(self, serializer_field):
        team_id = context_team_id(serializer_field.context)
        if team_id is None:
            # Never write a team-owned row without knowing whose it is.
            raise serializers.ValidationError("No team to create this row for.")
        return team_id

    def __repr__(self):
        return f"{self.__class__.__name__}()"


def _scope_related_field(field, team_id, writable):
    queryset = getattr(field, "queryset", None)
    if queryset is None or team_lookup(queryset.model) is None:
        return
    if team_id is None:
        # No request and no team: a write without a team refers to nothing.
        field.queryset = queryset.none()
    else:
        field.queryset = scope_to_team(queryset, team_id, writable=writable)


class TeamScopedModelSerializer(serializers.ModelSerializer):
    """A ModelSerializer that writes for the caller's team only.

    * A model that stores its team gets a hidden ``team_id`` field whose
      value is the caller's team: a ``team_id`` in the request body is
      ignored, and the model's unique-together validators see the team.
    * Every related field that accepts ids (foreign keys, many-to-many) is
      narrowed to the rows the caller's team may reference, so the id of a
      row of another team is refused like an unknown id ("Invalid pk ...
      object does not exist"), and its existence is not revealed. The key a
      derived model takes its team from accepts the team's own rows only.
    """

    def get_fields(self):
        fields = super().get_fields()
        model = self.Meta.model
        team_id = context_team_id(self.context)
        owner = owner_field(model)
        for name, field in fields.items():
            if getattr(field, "read_only", False):
                continue
            target = getattr(field, "child_relation", field)
            _scope_related_field(target, team_id, writable=(name == owner))
        if team_lookup(model) == TEAM_FIELD:
            fields[TEAM_FIELD] = serializers.HiddenField(default=CurrentTeamDefault())
        return fields


class TeamScopedFilterBackend(DjangoFilterBackend):
    """DjangoFilterBackend whose model-choice filters see the caller's rows.

    A filter on a foreign key validates the id against the related model.
    Unscoped, an id of another team was a valid choice (an empty page) and
    an unknown id was not (400): the difference told a team which ids exist
    elsewhere.
    """

    def get_filterset(self, request, queryset, view):
        filterset = super().get_filterset(request, queryset, view)
        if filterset is None:
            return None
        team_id = request_team_id(request)
        for filter_ in filterset.filters.values():
            if not isinstance(filter_, (ModelChoiceFilter, ModelMultipleChoiceFilter)):
                continue
            choices = filter_.get_queryset(request)
            if choices is not None and team_lookup(choices.model) is not None:
                # The filter builds its form field from .queryset (django-
                # filter's QuerySetRequestMixin), not from extra.
                filter_.queryset = scope_to_team(choices, team_id)
        return filterset


class TeamScopedViewSetMixin:
    """Every row a viewset reads, changes, deletes or acts on is the caller's.

    ``get_queryset`` is narrowed to the caller's team, so list endpoints
    leave other teams' rows out and ``get_object`` -- every detail route and
    detail action -- answers 404 for them, as for a row that does not exist
    (a 403 would confirm it does). A request that changes something sees
    the team's own rows only: shared reference rows are read-only. Custom
    actions must start from ``self.get_queryset()`` or
    ``self.team_queryset(Model)``, never from ``Model.objects``.
    """

    def get_team_id(self):
        return request_team_id(self.request)

    def writes(self):
        return self.request.method not in SAFE_METHODS

    def get_queryset(self):
        queryset = super().get_queryset()
        return scope_to_team(queryset, self.get_team_id(), writable=self.writes())

    def team_queryset(self, model_or_queryset, *, writable=None):
        """Another model's rows, as the caller's team may see them."""
        queryset = getattr(model_or_queryset, "_default_manager", None)
        queryset = queryset.all() if queryset is not None else model_or_queryset
        if writable is None:
            writable = self.writes()
        return scope_to_team(queryset, self.get_team_id(), writable=writable)

    def filter_queryset(self, queryset):
        for backend in list(self.filter_backends):
            if backend is DjangoFilterBackend:
                backend = TeamScopedFilterBackend
            queryset = backend().filter_queryset(self.request, queryset, self)
        return queryset


def record_team_task(async_result, team_id):
    """Remember which team dispatched a Celery task, for its status route."""
    from apps.core.models import TeamTask

    TeamTask.objects.get_or_create(
        task_id=str(async_result.id), defaults={"team_id": normalize_team_id(team_id)}
    )
    return async_result
