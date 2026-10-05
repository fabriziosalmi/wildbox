"""
The identity a playbook run acts for (#616).

A run is started by a user, through the gateway, and every call it makes to
another Wildbox service is made on that user's behalf. The tools, agents,
guardian and data services authenticate a request by the gateway's identity
headers (X-Wildbox-User-ID, X-Wildbox-Team-ID, X-Wildbox-Role) together with
the X-Gateway-Secret proof of origin, so that is what the connectors send:
the identity of the user who started the run, never a service identity of
the responder's own, which would have rights no user was given.

The caller is recorded when the run is started (start_execution) from the
user the gateway authenticated, travels with the run's message to the
worker, and is set for the duration of the run by run_as(). Connectors read
it through gateway_headers() at the moment they send a request.

It is a ContextVar, scoped like the agents service's caller identity (#594):
a Dramatiq worker thread runs one message after another, so a value set by
one run and never reset would still be there for the next. run_as() validates
the caller before setting anything and restores the previous value on exit,
whatever happens. Code that hands a step to another thread must run it under
contextvars.copy_context() for the identity to follow; a thread started
without it sees no caller, and its connector calls are refused rather than
sent without one.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterator, Mapping, Optional

from open_security_shared.scopes import AUTH_TYPE_HEADER, AUTH_TYPE_SERVICE

from .config import settings

VALID_ROLES = ("owner", "admin", "member", "viewer")

_run_caller: ContextVar[Optional[Dict[str, str]]] = ContextVar(
    "responder_run_caller", default=None
)


class CallerIdentityUnavailable(RuntimeError):
    """A run, or a call it makes, has no complete caller identity to act for.

    Raised when a run is started or executed without the user who started
    it, and when a connector is about to call a service with no caller set
    or no GATEWAY_INTERNAL_SECRET configured. Such a call is never sent:
    the receiving service would refuse it, and sending it under some other
    identity would act for someone who did not ask.
    """


def require_caller(caller: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """Return ``caller`` as the identity to record and forward, or refuse it.

    A complete caller has a non-blank ``user_id`` and ``team_id`` and, if
    given, one of the roles the gateway issues; the role defaults to
    ``member``, as in the services' own gateway authentication. Nothing
    missing is filled in from anywhere else.

    Raises:
        CallerIdentityUnavailable: ``caller`` is missing or incomplete.
    """
    if not isinstance(caller, Mapping):
        raise CallerIdentityUnavailable("the run has no caller identity")
    user_id = str(caller.get("user_id") or "").strip()
    team_id = str(caller.get("team_id") or "").strip()
    missing = [
        name
        for name, value in (("user_id", user_id), ("team_id", team_id))
        if not value
    ]
    if missing:
        raise CallerIdentityUnavailable(
            "the run's caller identity is incomplete: no " + " and no ".join(missing)
        )
    role = str(caller.get("role") or "").strip() or "member"
    if role not in VALID_ROLES:
        raise CallerIdentityUnavailable(
            f"the run's caller has an unknown role: {role!r}"
        )
    return {"user_id": user_id, "team_id": team_id, "role": role}


@contextmanager
def run_as(caller: Optional[Mapping[str, Any]]) -> Iterator[Dict[str, str]]:
    """Run a block with ``caller`` as the identity its service calls carry.

    The caller is validated before anything is set, so a missing or partial
    caller raises CallerIdentityUnavailable before the block runs. On exit,
    normal or not, the previous value is restored.
    """
    identity = require_caller(caller)
    token = _run_caller.set(identity)
    try:
        yield identity
    finally:
        _run_caller.reset(token)


def current_caller() -> Optional[Dict[str, str]]:
    """The caller of the run executing in this context, if any."""
    return _run_caller.get()


def gateway_headers() -> Dict[str, str]:
    """The headers that authenticate a service call as the run's caller.

    The same headers the gateway puts on a request it forwards for that user
    (open_security_shared.gateway_auth checks them), built per call from the
    run's caller and GATEWAY_INTERNAL_SECRET.

    Raises:
        CallerIdentityUnavailable: no caller is set in this context, or
            GATEWAY_INTERNAL_SECRET is not configured. The message says which.
    """
    caller = _run_caller.get()
    secret = settings.gateway_internal_secret
    missing = []
    if not caller:
        missing.append("no caller identity is set for this run")
    if not secret:
        missing.append("GATEWAY_INTERNAL_SECRET is not set")
    if missing:
        raise CallerIdentityUnavailable(
            "Cannot authenticate a call to a Wildbox service: " + "; ".join(missing)
        )
    return {
        "X-Wildbox-User-ID": caller["user_id"],
        "X-Wildbox-Team-ID": caller["team_id"],
        "X-Wildbox-Role": caller["role"],
        # What this call is (#637): a Wildbox service acting for the run's
        # caller, whose own credential the gateway checked when the run was
        # started. The services refuse a request that needs a scope and does
        # not say what its credential is.
        AUTH_TYPE_HEADER: AUTH_TYPE_SERVICE,
        "X-Gateway-Secret": secret,
    }
