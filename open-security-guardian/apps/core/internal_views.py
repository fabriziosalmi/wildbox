"""Routes other Wildbox services call on the internal network (#676).

They are not part of the API: the gateway proxies /api/v1/ only, so nothing
here is reachable through it, and GatewayAuthMiddleware, which authenticates
/api/, does not look at these paths. Each view therefore proves the caller
itself, with the secret the gateway and the services share
(GATEWAY_INTERNAL_SECRET, the same proof of origin guardian requires for the
gateway's X-Wildbox-* headers). Without that secret configured the route
refuses everything: there is no way to use it unauthenticated.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import uuid

from apps.core.memberships import revoke_membership, revoke_user
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

#: The most items one notice may carry; identity sends at most this many.
MAX_ITEMS = 1000
#: A notice is a list of ids: anything much larger is not one.
MAX_BODY_BYTES = 256 * 1024


def _refuse_unless_internal(request):
    """None if the caller holds the internal secret, else the refusal."""
    secret = os.getenv("GATEWAY_INTERNAL_SECRET")
    if not secret:
        # Fail closed: with no secret there is nothing to tell identity from
        # anyone else who can reach this port.
        logger.error(
            "[INTERNAL] GATEWAY_INTERNAL_SECRET not configured: refusing %s",
            request.path,
        )
        return JsonResponse(
            {
                "error": "service_misconfigured",
                "code": "GATEWAY_SECRET_NOT_CONFIGURED",
            },
            status=503,
        )
    provided = request.META.get("HTTP_X_GATEWAY_SECRET", "")
    if not hmac.compare_digest(provided.encode(), secret.encode()):
        logger.warning("[INTERNAL] Refused %s: no valid internal secret", request.path)
        return JsonResponse(
            {"error": "forbidden", "code": "GATEWAY_SECRET_REQUIRED"}, status=403
        )
    return None


def _bad_request(message):
    return JsonResponse({"error": "invalid_request", "message": message}, status=400)


def _uuid(value):
    if not isinstance(value, str):
        raise ValueError("an id must be a string")
    return uuid.UUID(value)


# No CSRF token: this is a call between services, authenticated by the
# secret header on every request, with no cookie or session to forge.
@method_decorator(csrf_exempt, name="dispatch")
class RevokeTeamMembershipsView(View):
    """identity says who is no longer a member of a team.

    ``POST`` one of:

    * ``{"memberships": [{"user_id": "<uuid>", "team_id": "<uuid>"}, ...]}``:
      each user left that team (a member was removed from it);
    * ``{"users": ["<uuid>", ...]}``: each account is gone, from every team.

    Answers ``{"revoked": <items handled>, "scope": "memberships"|"users"}``
    once every item is done, which is what identity waits for. A user
    guardian never saw counts as handled: there is nothing left to revoke.
    Anything else in the body is refused with 400, so that a notice guardian
    did not understand is never mistaken for one it acted on.
    """

    http_method_names = ["post"]

    def post(self, request):
        refusal = _refuse_unless_internal(request)
        if refusal is not None:
            return refusal

        if len(request.body) > MAX_BODY_BYTES:
            return _bad_request("The body is too large.")
        try:
            body = json.loads(request.body or b"")
        except ValueError:
            return _bad_request("The body is not JSON.")
        if not isinstance(body, dict) or set(body) not in ({"memberships"}, {"users"}):
            return _bad_request("Send either 'memberships' or 'users'.")

        ((scope, items),) = body.items()
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
            return _bad_request(f"'{scope}' must list 1 to {MAX_ITEMS} items.")
        try:
            if scope == "memberships":
                parsed = [self._membership(item) for item in items]
            else:
                parsed = [_uuid(item) for item in items]
        except (ValueError, KeyError, TypeError, AttributeError):
            return _bad_request(f"'{scope}' holds an item that is not valid.")

        # Everything was valid before anything is changed.
        if scope == "memberships":
            for team_id, user_id in parsed:
                revoke_membership(team_id, user_id)
        else:
            for user_id in parsed:
                revoke_user(user_id)
        return JsonResponse({"revoked": len(parsed), "scope": scope})

    @staticmethod
    def _membership(item):
        if not isinstance(item, dict) or set(item) != {"user_id", "team_id"}:
            raise ValueError("a membership names a user_id and a team_id")
        return _uuid(item["team_id"]), _uuid(item["user_id"])
