"""The role a service acts on is the one the gateway forwards (#788).

Guardian lets every member of a team read and only its owner and admins
write (``IsGatewayAdminOrReadOnly``), by the role in ``X-Wildbox-Role``. The
gateway sets that header from identity's answer for the credential, after
removing whatever the client sent. Two tests, on the running stack: a member
is refused a write an owner is allowed, and the role guardian acts on is
identity's for that member, whatever header the client adds.

What this module was. Its four tests could not fail for what their names
said, and its own runner, ``run_tests()``, counted the return value of
tests that return nothing: 0 of 4, whatever happened.

* ``test_rbac_user_forbidden_admin_endpoint`` asked for a list with the
  admin's key and required a 200: no user, and nothing forbidden. It is
  rewritten below.
* ``test_rbac_role_header_propagation`` passed on a 200, a 401 or a 403.
  It is rewritten below.
* ``test_error_handling_service_failure`` ran the ``all_star_e2e`` playbook
  on a stack where every service is up, and passed for a run that
  completed, for one that failed, for a status route that did not answer
  and for any refusal but a 500. Nothing fails in this stack, and a test
  here cannot stop a service the other modules are using: removed. What it
  named is tested where a failure can be made:
  ``test_all_star_carries_on_when_the_services_fail`` in
  ``open-security-responder/tests/unit/test_shipped_playbooks_run.py``
  (the services answer 503 and 500), and ``tests/chaos`` on a stack of its
  own (a service is stopped).
* ``test_malicious_ip_vulnerability_creation`` ran the same playbook on a
  private address and passed whether or not a vulnerability step existed.
  The playbook records a vulnerability for an address that threat
  intelligence scores as a threat or that shows more than two open ports;
  here the tools refuse to scan an internal address (#614) and a verdict
  on a public one depends on the runner's egress, so the step never runs:
  removed. ``test_all_star_records_a_known_threat`` in the same unit module
  covers it, and ``test_responder_guardian_actions.py`` covers a playbook's
  guardian actions on this stack.

Rate limiting is not tested here either (#776): the per-address limits and
their 429 against the gateway image itself (open-security-gateway/test/
rate_limit_tests.py; the stacks this suite runs against raise those limits
so that it cannot meet them), and the per-team budget and its
``X-RateLimit-*`` headers in test_gateway_security.py's test_rate_limiting.

Each test registers its own accounts directly at identity, as
test_guardian_tenancy.py does, and makes every other request through the
gateway, once.
"""

import os
import secrets
import uuid

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "https://localhost").rstrip("/")
IDENTITY_URL = os.getenv("IDENTITY_SERVICE_URL", "http://localhost:8001").rstrip("/")
TIMEOUT = 15

IDENTITY_API = f"{GATEWAY_URL}/api/v1/identity"
# /api/v1/guardian/<x> on the gateway is /api/v1/<x> on guardian.
GROUPS = f"{GATEWAY_URL}/api/v1/guardian/assets/groups/"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def login(email, password):
    response = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/jwt/login",
        data={"username": email, "password": password},
        timeout=TIMEOUT,
    )
    assert response.status_code == 200, response.text[:200]
    return response.json()["access_token"]


def new_owner():
    """Bearer headers of a newly registered account: the owner of its team."""
    email = f"gateway-hardening-{secrets.token_hex(6)}@example.com"
    password = f"Gateway-Hardening-{secrets.token_hex(8)}!"
    registered = requests.post(
        f"{IDENTITY_URL}/api/v1/auth/register",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    assert registered.status_code == 201, registered.text[:200]
    return bearer(login(email, password))


def team_of(headers):
    """The team the gateway resolves for a session."""
    response = requests.get(GROUPS, headers=headers, timeout=TIMEOUT)
    assert response.status_code == 200, response.text[:200]
    return response.headers["X-Wildbox-Team-ID"]


def new_member(owner, team_id, role):
    """Bearer headers of an account the owner creates in the team with
    ``role``, past its first password change."""
    email = f"gateway-hardening-{role}-{secrets.token_hex(6)}@example.com"
    initial = f"Gateway-Member-{secrets.token_hex(8)}!"
    created = requests.post(
        f"{IDENTITY_API}/admin/teams/{team_id}/members",
        json={"email": email, "password": initial, "role": role},
        headers=owner,
        timeout=TIMEOUT,
    )
    assert created.status_code == 201, created.text[:200]
    assert created.json()["role"] == role
    changed = requests.post(
        f"{IDENTITY_API}/admin/me/change-password",
        json={
            "current_password": initial,
            "new_password": f"Gateway-Member-{secrets.token_hex(8)}!",
        },
        headers=bearer(login(email, initial)),
        timeout=TIMEOUT,
    )
    assert changed.status_code == 200, changed.text[:200]
    return bearer(changed.json()["access_token"])


def create_group(headers, name):
    return requests.post(GROUPS, json={"name": name}, headers=headers, timeout=TIMEOUT)


def group_names(headers):
    """The names of the team's asset groups: a new team's fit one page."""
    response = requests.get(GROUPS, headers=headers, timeout=TIMEOUT)
    assert response.status_code == 200, response.text[:300]
    assert response.json()["next"] is None
    return {group["name"] for group in response.json()["results"]}


def delete_group(headers, created):
    requests.delete(
        f"{GROUPS}{created.json()['id']}/", headers=headers, timeout=TIMEOUT
    )


def test_rbac_user_forbidden_admin_endpoint():
    """A member reads the team's asset groups and is refused creating one."""
    owner = new_owner()
    member = new_member(owner, team_of(owner), "member")
    by_owner = f"it-hardening-{uuid.uuid4().hex[:12]}"
    by_member = f"it-hardening-{uuid.uuid4().hex[:12]}"

    # The route is not closed to everyone: the owner creates a group.
    created = create_group(owner, by_owner)
    assert created.status_code == 201, created.text[:300]
    try:
        # The member is in the team: it reads what the owner created.
        assert by_owner in group_names(member)

        refused = create_group(member, by_member)

        assert refused.status_code == 403, refused.text[:300]
        # And nothing was created.
        assert by_member not in group_names(owner)
    finally:
        delete_group(owner, created)


def test_rbac_role_header_propagation():
    """Guardian acts on the role identity holds for the caller: an admin
    writes, a member does not, and a role the client writes changes nothing."""
    owner = new_owner()
    team_id = team_of(owner)
    admin = new_member(owner, team_id, "admin")
    member = new_member(owner, team_id, "member")
    by_admin = f"it-hardening-{uuid.uuid4().hex[:12]}"
    forged = f"it-hardening-{uuid.uuid4().hex[:12]}"

    # Two accounts of one team, created the same way: the role is all that
    # tells them apart, and guardian has it from the gateway only.
    created = create_group(admin, by_admin)
    assert created.status_code == 201, created.text[:300]
    try:
        assert create_group(member, forged).status_code == 403

        # The member's own word for its role: the gateway removes the header
        # before it writes its own.
        for claimed in ("owner", "admin"):
            answer = create_group({**member, "X-Wildbox-Role": claimed}, forged)
            assert answer.status_code == 403, (claimed, answer.text[:300])

        names = group_names(owner)
        assert by_admin in names and forged not in names
    finally:
        delete_group(owner, created)
