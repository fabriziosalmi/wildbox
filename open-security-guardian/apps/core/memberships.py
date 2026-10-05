"""What guardian does when identity says a member left a team (#676).

guardian recorded a ``TeamMembership`` row the first time the gateway
authenticated a user in a team, and nothing ever removed it. A member that
identity removed from a team could no longer authenticate in it, but stayed
one of its users here: the team could go on assigning vulnerabilities to
them and sharing dashboards with them, and its data went on naming them as
the assignee, the owner, the approver.

identity now tells guardian (``POST /internal/team-memberships/revoke/``,
apps.core.views.RevokeTeamMembershipsView), and this module acts on it:

* the membership row is deleted, so the user is refused wherever a team
  names a user (apps.core.tenancy narrows every such field to the current
  members);
* the roles the user held in that team's rows are cleared: nobody is left
  assigned, owning or approving in a team they are no longer in, and an SLA
  or assignment e-mail about that team's data has nobody to go to.

Roles and records are different things, and only roles are cleared. A role
(``ROLE_FIELDS``) says who is responsible or has access now: it must not
outlive the membership. A record (``RECORD_FIELDS``) says who did something
-- created a row, approved an exception, wrote a note -- when they were a
member; it is the team's own history, and stays true after they leave.
Every relation from a team-owned model to a user is in one list or the
other; tests/unit/test_team_membership_revocation.py fails for one that is
in neither, so a new field cannot be cleared, or kept, by accident.

A notice can be lost (guardian down while identity removes the member).
The window on ``last_seen`` is what holds then: see
apps.core.tenancy.current_memberships.
"""

from __future__ import annotations

import logging

from apps.core.tenancy import normalize_team_id, team_lookup, team_q
from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import transaction

logger = logging.getLogger(__name__)

#: Who is responsible for a row, or has access to it, now. Cleared when the
#: user leaves the row's team. "app_label.Model": field names.
ROLE_FIELDS = {
    "assets.Asset": ("owner", "technical_contact"),
    "vulnerabilities.Vulnerability": ("assigned_to",),
    "remediation.RemediationTicket": ("assigned_to",),
    "remediation.RemediationWorkflow": ("assigned_to", "approver"),
    "remediation.RemediationStep": ("assigned_to",),
    "compliance.ComplianceAssessment": ("assessor",),
    "reporting.Dashboard": ("shared_with",),
}

#: Who did something, when they were a member. Kept: the team's history.
RECORD_FIELDS = {
    "assets.Asset": ("created_by",),
    "assets.AssetGroup": ("created_by",),
    "assets.AssetDiscoveryRule": ("created_by",),
    "vulnerabilities.Vulnerability": ("created_by",),
    "vulnerabilities.VulnerabilityAssessment": ("assessed_by",),
    "vulnerabilities.VulnerabilityNote": ("author",),
    "vulnerabilities.VulnerabilityHistory": ("changed_by",),
    "vulnerabilities.VulnerabilityAttachment": ("uploaded_by",),
    "remediation.RemediationTicket": ("created_by",),
    "remediation.RemediationWorkflow": ("created_by",),
    "remediation.RemediationComment": ("author",),
    "remediation.RemediationTemplate": ("created_by",),
    "compliance.ComplianceEvidence": ("collected_by",),
    "compliance.ComplianceResult": ("tested_by", "reviewed_by"),
    "compliance.ComplianceException": ("requested_by", "approved_by"),
    "integrations.ExternalSystem": ("created_by",),
    "integrations.IntegrationLog": ("user",),
    "integrations.NotificationChannel": ("created_by",),
    "reporting.ReportTemplate": ("created_by",),
    "reporting.ReportSchedule": ("created_by",),
    "reporting.Report": ("generated_by",),
    "reporting.Dashboard": ("created_by",),
    "reporting.Widget": ("created_by",),
    "reporting.AlertRule": ("created_by",),
    "scanners.Scanner": ("created_by",),
    "scanners.ScanProfile": ("created_by",),
    "scanners.Scan": ("created_by",),
    "scanners.ScanSchedule": ("created_by",),
}


def user_relations():
    """(model, field) for every relation from a team-owned model to a user."""
    user_model = get_user_model()
    found = []
    for model in apps.get_models():
        if model is user_model or team_lookup(model) is None:
            continue
        for field in model._meta.get_fields():
            if (
                field.auto_created
                or getattr(field, "related_model", None) is not user_model
            ):
                continue
            found.append((model, field))
    return found


def _role_fields():
    for label, names in ROLE_FIELDS.items():
        model = apps.get_model(label)
        for name in names:
            yield model, model._meta.get_field(name)


def _mirror(user_id):
    """The auth.User that mirrors an identity user id, or None if never seen."""
    return get_user_model().objects.filter(username=str(user_id)).first()


def _clear_roles(user, team_id=None):
    """Clear every role ``user`` holds, in one team's rows or in all teams'.

    Returns {"app_label.Model.field": rows changed}, for the fields that
    changed. Shared reference rows are not a team's and are never touched.
    """
    cleared = {}
    for model, field in _role_fields():
        rows = model._default_manager.all()
        if team_id is not None:
            rows = rows.filter(team_q(model, team_id, writable=True))
        rows = rows.filter(**{field.name: user})
        key = f"{model._meta.label}.{field.name}"
        if field.many_to_many:
            count = 0
            for row in rows:
                getattr(row, field.name).remove(user)
                count += 1
        else:
            pks = list(rows.values_list("pk", flat=True))
            count = len(pks)
            if count:
                _record_unassignment(model, field, pks)
                # update(), not save(): no post_save work (enrichment, the
                # assignment e-mail) for what is not an edit by anyone.
                model._default_manager.filter(pk__in=pks).update(**{field.name: None})
        if count:
            cleared[key] = count
    return cleared


def _record_unassignment(model, field, pks):
    """Say in a vulnerability's history why it lost its assignee."""
    if (
        model._meta.label != "vulnerabilities.Vulnerability"
        or field.name != "assigned_to"
    ):
        return
    from apps.vulnerabilities.models import VulnerabilityHistory

    VulnerabilityHistory.objects.bulk_create(
        VulnerabilityHistory(
            vulnerability_id=pk,
            field_name="assigned_to",
            old_value="assigned",
            new_value="",
            change_reason="Unassigned: the assignee is no longer a member of the team",
        )
        for pk in pks
    )


def revoke_membership(team_id, user_id):
    """A user left a team: delete the membership, clear their roles in it.

    ``user_id`` is identity's user id. Returns the fields cleared (see
    ``_clear_roles``). A user guardian never saw has nothing to revoke: that
    is a success with nothing cleared, not an error, so identity can confirm
    the removal of a member who never used guardian.
    """
    from apps.core.models import TeamMembership

    team_id = normalize_team_id(team_id)
    if team_id is None:
        raise ValueError("revoke_membership needs a team")
    user = _mirror(user_id)
    if user is None:
        return {}
    with transaction.atomic():
        TeamMembership.objects.filter(team_id=team_id, user=user).delete()
        cleared = _clear_roles(user, team_id)
    logger.info(
        "Membership revoked: user %s left team %s; roles cleared: %s",
        user_id,
        team_id,
        cleared or "none",
    )
    return cleared


def revoke_user(user_id):
    """An account is gone: delete all its memberships, clear all its roles.

    For an account identity deleted. Roles are cleared in every team's rows,
    whatever membership rows are left: a role must not outlive the account
    because its membership row had already expired.
    """
    from apps.core.models import TeamMembership

    user = _mirror(user_id)
    if user is None:
        return {}
    with transaction.atomic():
        TeamMembership.objects.filter(user=user).delete()
        cleared = _clear_roles(user)
    logger.info(
        "Memberships revoked: account %s is gone; roles cleared: %s",
        user_id,
        cleared or "none",
    )
    return cleared
