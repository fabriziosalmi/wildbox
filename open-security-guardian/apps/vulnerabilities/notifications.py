"""The e-mails about a vulnerability: past its due date, and assigned (#705).

Both were addressed to ``assigned_to.email``, which guardian's mirror of an
identity user never had, so neither reached anybody; and both linked
``<GUARDIAN_BASE_URL>/vulnerabilities/<id>/``, a page the dashboard does not
have. Who is told is now decided by apps.core.notifications:

* an SLA violation: the assignee, while a member of the vulnerability's
  team with an active account; otherwise the team's owners and admins, who
  are the ones to hear that a vulnerability nobody holds is overdue;
* an assignment: the assignee, and nobody else. Telling the owners that
  somebody else was assigned something would tell them nothing.

What became of each is written in the vulnerability's history, where its
team reads it.
"""

from __future__ import annotations

from apps.core.notifications import (
    AUDIENCE_ADMINS,
    NO_MAIL_SERVER,
    ContactsUnavailable,
    Delivery,
    dashboard_link,
    mail_problem,
    notify_team_from_template,
)

#: What every history entry of an assignment notification starts with.
ASSIGNMENT_HISTORY_MARKER = "Assignment notification"

#: In the history entry of a violation the owners and admins were told of,
#: because there was no assignee to tell.
SLA_NO_ASSIGNEE = "no assignee to e-mail"
SLA_TOLD_ADMINS = f"sent to the team's owners and admins ({SLA_NO_ASSIGNEE})"


def _context(vulnerability, **extra):
    return {
        "vulnerability": vulnerability,
        # The team's list of vulnerabilities: the dashboard has no page for
        # a single one. None without GUARDIAN_BASE_URL, and then no link.
        "link": dashboard_link("vulnerabilities"),
        **extra,
    }


def sla_outcome(delivery):
    """What the history says of an SLA notification."""
    if delivery.sent and delivery.audience == AUDIENCE_ADMINS:
        return SLA_TOLD_ADMINS
    return delivery.outcome


def notify_sla_violation(vulnerability, overdue_hours, last_outcome, directory):
    """Tell somebody that ``vulnerability`` is past its due date.

    The Delivery, or None when there is nothing to do or say that the last
    history entry (``last_outcome``, '' if none) does not already say:

    * the owners and admins are told once of a violation with no assignee
      to tell, not once a day: the daily reminder is for the person who can
      act on it;
    * a reason only a person can remove (no mail server, nobody with an
      address) is recorded once, not once a day for every overdue
      vulnerability.

    A failure that can pass (identity or the mail server not answering) is
    recorded each time, and tried again a day later.
    """
    if mail_problem():
        if NO_MAIL_SERVER in last_outcome:
            return None
        return Delivery(sent=False, reason=NO_MAIL_SERVER)

    team_id = vulnerability.asset.team_id
    assignee = vulnerability.assigned_to
    try:
        address = directory.member_address(team_id, assignee)
    except ContactsUnavailable as exc:
        delivery = Delivery(sent=False, reason=exc.reason, retry=exc.retry)
    else:
        if address is None and last_outcome == SLA_TOLD_ADMINS:
            return None
        delivery = notify_team_from_template(
            team_id,
            f"SLA Violation: {vulnerability.title} - {overdue_hours:.1f}h overdue",
            "vulnerabilities/sla_violation.html",
            _context(
                vulnerability,
                overdue_hours=overdue_hours,
                no_assignee=address is None,
            ),
            member=assignee,
            directory=directory,
            kind="sla",
        )
    if not delivery.sent and not delivery.retry and delivery.outcome == last_outcome:
        return None
    return delivery


def notify_assignment(vulnerability, directory=None):
    """Tell the assignee that ``vulnerability`` is theirs; the Delivery."""
    return notify_team_from_template(
        vulnerability.asset.team_id,
        f"Vulnerability Assigned: {vulnerability.title}",
        "vulnerabilities/assignment.html",
        _context(vulnerability),
        member=vulnerability.assigned_to,
        fallback=False,
        directory=directory,
        kind="assignment",
    )
