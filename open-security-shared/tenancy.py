"""Reusable tenancy helpers.

One place to scope ORM queries to the caller's team, so downstream services
enforce data isolation the same way instead of reinventing it. Pair with the
gateway-auth dependency (`get_user_from_gateway_headers`) and `require_role`.

The helpers are intentionally ORM-library-agnostic: they only build the
`model.team_id == user.team_id` expression, which works with both the legacy
SQLAlchemy Query API and the 2.0 `select()` API, so importing this module pulls
no extra dependencies.
"""

from typing import Any

from .gateway_auth import GatewayUser

__all__ = ["team_filter", "scope_query", "scope_select"]


def team_filter(model: Any, user: GatewayUser):
    """Return a filter expression scoping ``model`` to the caller's team.

    Usage::

        db.query(Model).filter(team_filter(Model, user))      # legacy Query API
        select(Model).where(team_filter(Model, user))         # SQLAlchemy 2.0
    """
    return model.team_id == user.team_id


def scope_query(query: Any, model: Any, user: GatewayUser):
    """Scope a legacy SQLAlchemy ``Query`` (``db.query(Model)``) to the team."""
    return query.filter(team_filter(model, user))


def scope_select(stmt: Any, model: Any, user: GatewayUser):
    """Scope a SQLAlchemy 2.0 ``select()`` statement to the team."""
    return stmt.where(team_filter(model, user))
