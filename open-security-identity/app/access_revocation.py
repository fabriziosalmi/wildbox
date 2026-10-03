"""
Disable credentials at the gateway before identity commits the change (#593).

The gateway caches each authorization decision for AUTH_CACHE_TTL (300 s by
default). Revoking an API key only set it inactive in the database, so a key
revoked because it leaked kept working for up to five minutes on every route
the gateway authenticates; deactivating, deleting or removing the account
behind a key did the same, or flushed the cache best effort, after the
commit, with nothing to say whether the flush took effect.

Every change that disables a key now goes through here first. The gateway is
told which keys -- and, when the whole account goes, that the account's
sessions end -- and must confirm. Only then does the caller commit. If the
gateway cannot confirm, the change is not made and the caller answers 503:
a client can repeat it, while a change committed without the gateway would
leave the credentials usable at the gateway with no way to tell for how long.
That is the contract logout has had since #571 and a password change since
#569. Removing a member from a team also ends, in that team only, the
member's sessions (#613).

A password change does not revoke API keys, as #569 decided: keys are not
sessions, and a leaked key is revoked on its own, on the API keys page.
"""

import logging
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .logout import (
    RevocationError,
    revoke_api_keys,
    revoke_sessions_issued_before,
    revoke_team_sessions,
)
from .models import ApiKey

logger = logging.getLogger(__name__)


def revocation_unavailable(action: str) -> HTTPException:
    """The 503 a change answers when the gateway did not confirm it."""
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=(
            f"{action} was not done: the gateway could not confirm that it "
            "refuses the credentials concerned. Try again."
        ),
    )


async def active_api_key_ids(
    db: AsyncSession,
    *,
    user_id=None,
    team_ids: Optional[Iterable] = None,
) -> List[str]:
    """The ids of the active API keys of a user, of teams, or of a user in teams.

    Only active keys: an inactive one was revoked at the gateway when it was
    disabled, and identity refuses it.
    """
    query = select(ApiKey.id).where(ApiKey.is_active.is_(True))
    if user_id is not None:
        query = query.where(ApiKey.user_id == user_id)
    if team_ids is not None:
        team_ids = list(team_ids)
        if not team_ids:
            return []
        query = query.where(ApiKey.team_id.in_(team_ids))
    result = await db.execute(query)
    return [str(api_key_id) for api_key_id in result.scalars().all()]


async def revoke_api_keys_or_503(api_key_ids: Iterable, action: str) -> None:
    """Have the gateway refuse these keys, or raise the 503 for ``action``."""
    try:
        await revoke_api_keys(api_key_ids)
    except RevocationError as exc:
        logger.error("%s refused: the gateway did not confirm: %s", action, exc)
        raise revocation_unavailable(action) from exc


async def end_account_access_or_503(
    api_key_ids: Iterable, user_id, action: str
) -> datetime:
    """End, at the gateway, everything an account can authenticate with.

    For an account that is deactivated or deleted: its API keys
    (``api_key_ids``) and every session issued up to now. Returns that
    instant; the caller stores it in users.tokens_valid_after when the
    account remains, so the sessions stay ended in identity too should it
    be reactivated. Raises the 503 for ``action`` if the gateway does not
    confirm both.
    """
    not_before = datetime.now(timezone.utc)
    try:
        await revoke_api_keys(api_key_ids)
        await revoke_sessions_issued_before(user_id, not_before)
    except RevocationError as exc:
        logger.error("%s refused: the gateway did not confirm: %s", action, exc)
        raise revocation_unavailable(action) from exc
    return not_before


async def end_team_access_or_503(db: AsyncSession, user_id, team_id, action: str) -> None:
    """End, at the gateway, what a member could use a team with (#613).

    For a member removed from a team: their API keys for that team (#593)
    and, in that team only, every session issued up to now. A session is
    not bound to a team -- identity resolves one on every authorization --
    so the gateway held a decision "allowed in this team" for the removed
    member's sessions for up to its cache TTL. Their sessions go on working
    in the teams they still belong to. Raises the 503 for ``action`` if the
    gateway does not confirm both; the caller deletes the membership only
    after this returns.
    """
    api_key_ids = await active_api_key_ids(db, user_id=user_id, team_ids=[team_id])
    not_before = datetime.now(timezone.utc)
    try:
        await revoke_api_keys(api_key_ids)
        await revoke_team_sessions([(user_id, team_id)], not_before)
    except RevocationError as exc:
        logger.error("%s refused: the gateway did not confirm: %s", action, exc)
        raise revocation_unavailable(action) from exc
