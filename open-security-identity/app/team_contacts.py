"""
Who guardian may e-mail about a team's data (#705).

guardian sends e-mail about a team's vulnerabilities, alerts, reports and
compliance findings, and had no address to send it to: it mirrors identity's
users by id alone. identity is where an address, a role and an account's
state live, and where they change (the e-mail change of #569, a role
change, a deactivation, a removal from the team). So guardian does not keep
a copy that could go stale: its worker asks here, when it is about to send,
and gets the answer that is true at that moment.

``POST /internal/team-contacts`` answers, for one team, the members that may
be e-mailed about it:

* members of that team only: the join on the membership is the question,
  not a filter added to it;
* active accounts only. A deactivated account keeps its memberships and can
  be reactivated; while it is deactivated it is told nothing;
* and only the ones the caller selects: named users (an assignee), or the
  holders of given roles (the owners and admins, who receive what has no
  recipient of its own). There is no "everybody": a caller cannot list a
  team.

An address is returned as identity holds it. identity does not verify
addresses today (nothing sends a verification e-mail), so ``is_verified`` is
not required: an address is the one its user chose with their password
(#569), or the one a team administrator gave the account they created
(#573).

The caller proves itself with ``GUARDIAN_CONTACTS_SECRET``, a secret of its
own, not the gateway's. guardian's worker is the caller, and the worker
holds no ``GATEWAY_INTERNAL_SECRET`` on purpose: it runs scans and fetches
threat intelligence from outside, and that secret lets its holder speak as
any user to every service. This one opens this route and nothing else.
identity refuses to start when the two are the same value, so that an
operator cannot hand the worker the gateway's secret by reusing it. Unset,
the route answers 503 and guardian sends no e-mail, and says why.

The route is under /internal, which the gateway does not proxy.
"""

from __future__ import annotations

import hmac
import logging
import uuid
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .database import get_db
from .models import TeamMembership, TeamRole, User

logger = logging.getLogger(__name__)

router = APIRouter()

#: The header guardian's worker presents GUARDIAN_CONTACTS_SECRET in.
SECRET_HEADER = "X-Guardian-Contacts-Secret"

#: The most users one request may name. A sweep asks per team, for the
#: assignees whose notification is due.
MAX_USER_IDS = 200

Role = Literal["owner", "admin", "member"]


class TeamContactsRequest(BaseModel):
    """One team, and which of its members: named users, or role holders."""

    # A field this does not know is a question it would answer wrongly.
    model_config = ConfigDict(extra="forbid")

    team_id: uuid.UUID
    user_ids: Optional[List[uuid.UUID]] = Field(
        default=None, min_length=1, max_length=MAX_USER_IDS
    )
    roles: Optional[List[Role]] = Field(default=None, min_length=1, max_length=3)

    @model_validator(mode="after")
    def _exactly_one_selection(self) -> "TeamContactsRequest":
        if (self.user_ids is None) == (self.roles is None):
            raise ValueError(
                "name either user_ids or roles: there is no listing of a whole team"
            )
        return self


class TeamContact(BaseModel):
    user_id: str
    email: str
    role: str


class TeamContactsResponse(BaseModel):
    team_id: str
    contacts: List[TeamContact]


def require_contacts_secret(
    provided: Optional[str] = Header(None, alias=SECRET_HEADER),
) -> None:
    """Refuse a caller that does not hold GUARDIAN_CONTACTS_SECRET.

    A dependency of the route, so it is decided before the body is read: a
    caller without the secret learns nothing from how a body is refused.
    503 when identity has none: nobody can be the caller, and that is a
    deployment that has not switched guardian's e-mail on, not a caller's
    mistake. The comparison is constant-time.
    """
    expected = settings.guardian_contacts_secret
    if not expected:
        logger.warning(
            "Refused a team-contacts request: GUARDIAN_CONTACTS_SECRET is not set"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Team contacts are not configured (GUARDIAN_CONTACTS_SECRET)",
        )
    if not provided or not hmac.compare_digest(
        provided.encode("utf-8"), expected.encode("utf-8")
    ):
        logger.warning("Refused a team-contacts request: missing or wrong secret")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid contacts secret",
        )


def contacts_query(request: TeamContactsRequest):
    """The members of ``request.team_id`` the request selects, active only.

    The team and the account's state are conditions of the query itself, so
    no caller can leave them out; the selection narrows further.
    """
    query = (
        select(
            User.id,
            User.email,
            User.is_active,
            TeamMembership.team_id,
            TeamMembership.role,
        )
        .join(TeamMembership, TeamMembership.user_id == User.id)
        .where(TeamMembership.team_id == request.team_id)
        .where(User.is_active.is_(True))
    )
    if request.user_ids is not None:
        query = query.where(User.id.in_(request.user_ids))
    else:
        query = query.where(TeamMembership.role.in_(request.roles))
    return query.order_by(TeamMembership.joined_at.asc(), User.id.asc())


def select_contacts(rows, request: TeamContactsRequest) -> List[TeamContact]:
    """The rows that may be answered, checked again one by one.

    The query already says all of this. It is said twice because the answer
    is where a team's data will be sent: a row of another team, of a
    deactivated account or outside the selection is dropped here whatever
    the query returned, and an account without an address is nobody to
    write to.
    """
    wanted_users = (
        {uuid.UUID(str(user_id)) for user_id in request.user_ids}
        if request.user_ids is not None
        else None
    )
    wanted_roles = set(request.roles) if request.roles is not None else None
    known_roles = {role.value for role in TeamRole}
    contacts = []
    seen = set()
    for user_id, email, is_active, team_id, role in rows:
        user_id = uuid.UUID(str(user_id))
        if uuid.UUID(str(team_id)) != request.team_id:
            continue
        if is_active is not True or role not in known_roles:
            continue
        if wanted_users is not None and user_id not in wanted_users:
            continue
        if wanted_roles is not None and role not in wanted_roles:
            continue
        address = (email or "").strip()
        if not address or user_id in seen:
            continue
        seen.add(user_id)
        contacts.append(TeamContact(user_id=str(user_id), email=address, role=role))
    return contacts


@router.post(
    "/team-contacts",
    response_model=TeamContactsResponse,
    dependencies=[Depends(require_contacts_secret)],
)
async def team_contacts(
    request: TeamContactsRequest,
    db: AsyncSession = Depends(get_db),
):
    """The selected members of one team that may be e-mailed about it.

    A team that does not exist, or a user that is not in it, is an empty
    answer, as a member without an address is: the caller sends nothing
    either way.
    """
    result = await db.execute(contacts_query(request))
    contacts = select_contacts(result.all(), request)
    # Counts only: an address is not something to write to a log.
    logger.info(
        "Team contacts answered: team %s, %d contact(s) by %s",
        request.team_id,
        len(contacts),
        "user" if request.user_ids is not None else "role",
    )
    return TeamContactsResponse(team_id=str(request.team_id), contacts=contacts)
