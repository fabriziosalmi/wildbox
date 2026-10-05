"""
Tell guardian when a membership ends (#676).

guardian keeps its own record of which users it has seen acting in which
team, and lets a team name only those users: as the assignee of a
vulnerability, the owner of an asset, the people a dashboard is shared
with. Nothing told it when identity removed a member from a team, so the
removed member stayed one of that team's users in guardian for good.

Every change that ends a membership now ends with a notice to guardian, on
the internal network, with the secret the gateway and the services share:

* a member removed from a team: that user, in that team;
* an account deleted, by an administrator or by its owner: that user, in
  every team.

This is not the contract of access_revocation.py, and deliberately so. There
the gateway is told first and must confirm, or the change is not made (503):
the gateway is what lets a credential through, and it is always there. Here
the notice goes out after the change is committed, and a notice that cannot
be delivered does not undo it. Removing a member must not depend on guardian
being up: a removal refused because the vulnerability service is restarting
would leave the member with their access to everything, to protect a list
of assignable names. And by the time guardian is told, the gateway already
refuses the member in that team.

So a lost notice has to be safe on guardian's side, and it is: guardian
trusts a membership only for a limited time after the last request the user
made in the team (GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS), and a removed
member can make none. The notice makes the removal take effect at once; the
window makes it take effect regardless. A notice that fails is logged as an
error, so an operator can see it.

Deactivating an account sends no notice. A deactivated account keeps its
memberships in identity and can be reactivated; it cannot authenticate, so
its memberships age out in guardian by themselves.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Collection, Tuple

import httpx

from .gateway_cache import _RETRY_DELAYS, _unconfirmed

logger = logging.getLogger(__name__)

#: guardian's internal route. The trailing slash is part of the path: a
#: redirect to it would drop the body of a POST.
DEFAULT_URL = "http://open-security-guardian:8013/internal/team-memberships/revoke/"

#: The most items guardian accepts in one notice.
_MAX_ITEMS_PER_CALL = 1000

#: What a notice came to.
CONFIRMED = "confirmed"  # guardian answered that it handled every item
DISABLED = "disabled"  # no guardian to tell: GUARDIAN_INTERNAL_URL is empty
FAILED = "failed"  # guardian was not told, or did not confirm


def guardian_url() -> str:
    """Where guardian is told; empty when this deployment has no guardian.

    Unset means the default, the name guardian has on the Compose network.
    Set to an empty string, it switches the notice off.
    """
    return os.getenv("GUARDIAN_INTERNAL_URL", DEFAULT_URL).strip()


async def notify_memberships_ended(
    memberships: Collection[Tuple[str, str]], timeout: float = 2.0
) -> str:
    """Tell guardian that each ``(user_id, team_id)`` membership has ended.

    Call it after the removal is committed. Never raises: see the module
    docstring for why a failure does not undo the removal. Returns
    CONFIRMED, DISABLED or FAILED.
    """
    items = [
        {"user_id": str(user_id), "team_id": str(team_id)}
        for user_id, team_id in memberships
    ]
    return await _notify("memberships", items, timeout)


async def notify_accounts_ended(user_ids: Collection[str], timeout: float = 2.0) -> str:
    """Tell guardian that each account is gone, from every team.

    Call it after the deletion is committed. Never raises. Returns
    CONFIRMED, DISABLED or FAILED.
    """
    return await _notify("users", [str(user_id) for user_id in user_ids], timeout)


async def _notify(scope: str, items: list, timeout: float) -> str:
    if not items:
        return CONFIRMED
    url = guardian_url()
    if not url:
        logger.info(
            "guardian not told of %d ended %s: GUARDIAN_INTERNAL_URL is empty",
            len(items),
            scope,
        )
        return DISABLED
    try:
        for start in range(0, len(items), _MAX_ITEMS_PER_CALL):
            chunk = items[start : start + _MAX_ITEMS_PER_CALL]
            problem = await _post_confirmed(url, scope, chunk, timeout)
            if problem is not None:
                _log_failure(scope, len(items), problem)
                return FAILED
    except Exception as exc:  # noqa: BLE001 - the change is committed; never raise
        _log_failure(scope, len(items), type(exc).__name__)
        return FAILED
    return CONFIRMED


def _log_failure(scope: str, count: int, problem: str) -> None:
    logger.error(
        "guardian was not told of %d ended %s (%s). The change itself is done "
        "and the gateway refuses the access concerned; guardian goes on "
        "accepting the user as one of the team's users until their "
        "membership there ages out (GUARDIAN_TEAM_MEMBERSHIP_MAX_AGE_DAYS).",
        count,
        scope,
        problem,
    )


async def _post_confirmed(url: str, scope: str, items: list, timeout: float):
    """POST one notice, retried; why guardian did not confirm it, or None."""
    secret = os.getenv("GATEWAY_INTERNAL_SECRET")
    if not secret:
        return "GATEWAY_INTERNAL_SECRET is not set"

    problem = "no attempt made"
    for attempt, delay in enumerate((0.0, *_RETRY_DELAYS), start=1):
        if delay:
            await asyncio.sleep(delay)
        try:
            # No redirects: a 301 is not guardian's confirmation, and
            # following one would send the secret somewhere else.
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=False
            ) as client:
                response = await client.post(
                    url, json={scope: items}, headers={"X-Gateway-Secret": secret}
                )
            problem = _unconfirmed(response, len(items), scope)
            if problem is None:
                return None
        except Exception as exc:  # noqa: BLE001 - retried, then reported
            problem = type(exc).__name__
        logger.warning(
            "guardian membership notice attempt %d/%d not confirmed (%s)",
            attempt,
            len(_RETRY_DELAYS) + 1,
            problem,
        )
    return problem
