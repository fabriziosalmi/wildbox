"""
Vulnerability Management Tasks

Celery tasks for background processing of vulnerability data.
"""

from celery import shared_task
from django.utils import timezone
from django.conf import settings
import logging
import requests
from datetime import timedelta

from apps.core.locks import single_instance
from apps.core.notifications import TeamDirectory
from apps.core.tenancy import is_current_member

from .models import (
    Vulnerability, VulnerabilityStatus, VulnerabilityHistory,
    VulnerabilityAssessment
)
from .notifications import (
    ASSIGNMENT_HISTORY_MARKER,
    notify_assignment,
    notify_sla_violation,
    sla_outcome,
)

logger = logging.getLogger(__name__)


class NotificationNotDelivered(Exception):
    """A notification that may go through on another attempt."""


@shared_task(bind=True, max_retries=3)
@single_instance
def update_vulnerability_risk_scores(self, vulnerability_ids=None):
    """
    Recalculate risk scores for vulnerabilities
    
    Args:
        vulnerability_ids: List of vulnerability IDs to update, or None for all
    """
    try:
        if vulnerability_ids:
            vulnerabilities = Vulnerability.objects.filter(id__in=vulnerability_ids)
        else:
            vulnerabilities = Vulnerability.objects.filter(
                status__in=[VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS]
            )
        
        updated_count = 0
        for vuln in vulnerabilities.iterator():
            old_risk_score = vuln.risk_score
            vuln.save()  # This triggers risk score recalculation
            
            if abs(vuln.risk_score - old_risk_score) > 0.1:
                # Create history entry for significant risk score changes
                VulnerabilityHistory.objects.create(
                    vulnerability=vuln,
                    field_name='risk_score',
                    old_value=str(old_risk_score),
                    new_value=str(vuln.risk_score),
                    change_reason='Automated risk score recalculation'
                )
            
            updated_count += 1
        
        logger.info(f"Updated risk scores for {updated_count} vulnerabilities")
        return {'updated_count': updated_count}
        
    except Exception as exc:
        logger.error(f"Error updating vulnerability risk scores: {exc}")
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@shared_task(bind=True, max_retries=3)
def notify_vulnerability_assignment(self, vulnerability_id, assigned_by_user_id):
    """
    Tell the assignee that a vulnerability is theirs

    Args:
        vulnerability_id: ID of the assigned vulnerability
        assigned_by_user_id: ID of user who made the assignment. Not used:
            the e-mail named them by ``get_full_name()``, which guardian's
            mirror of an identity user does not have, and looked them up
            first, so a call without one failed (#705). Kept so that a task
            already queued still runs.

    The address is identity's, asked for now (apps.core.notifications), and
    what became of the notification is written in the vulnerability's
    history. A failure that can pass is tried again; the last attempt
    records it.
    """
    try:
        vulnerability = Vulnerability.objects.select_related(
            'asset', 'assigned_to'
        ).get(id=vulnerability_id)

        if vulnerability.assigned_to and member_assignee(vulnerability) is None:
            # Assigned to somebody who is not, or no longer, a member of the
            # vulnerability's team: the API refuses that, so this is a stale
            # assignment. Nothing about the team's data is e-mailed (#676).
            logger.warning(
                f"Assignment notification for vulnerability {vulnerability_id} not sent: "
                "the assignee is not a member of its team"
            )
            return {'notification_sent': False}

        if not vulnerability.assigned_to:
            # Assigned to a group: a group is a name, with no address.
            logger.warning(
                f"Assignment notification for vulnerability {vulnerability_id} not sent: "
                "it is assigned to a group, which has no address"
            )
            return {'notification_sent': False}

        delivery = notify_assignment(vulnerability)
        if delivery.retry and self.request.retries < self.max_retries:
            raise NotificationNotDelivered(delivery.reason)

        VulnerabilityHistory.objects.create(
            vulnerability=vulnerability,
            field_name='assignment_notification',
            old_value='',
            new_value='sent' if delivery.sent else 'not_sent',
            change_reason=f'{ASSIGNMENT_HISTORY_MARKER} {delivery.outcome}'
        )
        if not delivery.sent:
            logger.warning(
                f"Assignment notification for vulnerability {vulnerability_id} "
                f"{delivery.outcome}"
            )
        return {'notification_sent': delivery.sent}

    except Vulnerability.DoesNotExist:
        logger.error(f"Vulnerability {vulnerability_id} not found")
        return {'error': 'Vulnerability not found'}
    except Exception as exc:
        logger.error(f"Error sending assignment notification: {exc}")
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@shared_task(bind=True, max_retries=3)
def scan_vulnerability_remediation(self, vulnerability_id):
    """
    Check if vulnerability has been remediated by re-scanning
    
    Args:
        vulnerability_id: ID of vulnerability to check
    """
    try:
        vulnerability = Vulnerability.objects.get(id=vulnerability_id)
        
        # This would integrate with scanner APIs to verify remediation
        # Implementation depends on specific scanner being used
        
        # Example for generic HTTP-based scanner
        scanner_config = getattr(settings, 'SCANNER_CONFIG', {})
        if not scanner_config:
            logger.warning("No scanner configuration found")
            return {'error': 'No scanner configured'}
        
        # Placeholder for actual scanner integration
        remediation_verified = False  # Would be result of actual scan
        
        if remediation_verified:
            vulnerability.status = VulnerabilityStatus.RESOLVED
            vulnerability.resolved_at = timezone.now()
            vulnerability.metadata['remediation_verification'] = {
                'verified_at': timezone.now().isoformat(),
                'method': 'automated_scan'
            }
            vulnerability.save()
            
            # Create history entry
            VulnerabilityHistory.objects.create(
                vulnerability=vulnerability,
                field_name='status',
                old_value='open',
                new_value='resolved',
                change_reason='Automated remediation verification',
            )
            
            logger.info(f"Vulnerability {vulnerability_id} automatically closed - remediation verified")
            return {'verification_result': 'remediated'}
        else:
            logger.info(f"Vulnerability {vulnerability_id} still present after remediation check")
            return {'verification_result': 'still_present'}
            
    except Vulnerability.DoesNotExist:
        logger.error(f"Vulnerability {vulnerability_id} not found")
        return {'error': 'Vulnerability not found'}
    except Exception as exc:
        logger.error(f"Error checking vulnerability remediation: {exc}")
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


#: What every history entry of the SLA check starts with; the check finds its
#: own entries of the last day by it.
SLA_HISTORY_MARKER = 'SLA violation notification'


def member_assignee(vulnerability):
    """The vulnerability's assignee, if guardian counts them in its team.

    Its assignee, while a current member of the vulnerability's team (#676).
    identity tells guardian when a member leaves, and their assignments are
    cleared then; if that notice never arrived, this is what keeps a team's
    asset names and vulnerability titles from being e-mailed to somebody
    who left it. Whether they can be written to is identity's to say
    (apps.core.notifications). A vulnerability without a team (written
    before guardian kept one) keeps its assignee, and e-mails nobody: there
    is no team to ask identity about.
    """
    assignee = vulnerability.assigned_to
    if assignee is None:
        return None
    team_id = vulnerability.asset.team_id
    if team_id is not None and not is_current_member(assignee, team_id):
        return None
    return assignee


def _sla_outcome_of(entry):
    """The outcome a history entry of the SLA check recorded, '' for none."""
    if entry is None:
        return ''
    recorded = entry.change_reason[len(SLA_HISTORY_MARKER):].strip()
    return recorded.rsplit(' - ', 1)[0]


@shared_task
@single_instance
def check_sla_violations():
    """
    Record SLA violations and notify somebody of each

    The assignee, while a member of the vulnerability's team with an active
    account; otherwise the team's owners and admins (#705). Never an address
    for the whole platform: the check copied every violation to a
    SECURITY_TEAM_EMAIL setting, which would have received every team's
    asset names and vulnerability titles (#678).

    A violation is recorded in the vulnerability's history with what became
    of its notification: once a day while there is an assignee to remind,
    once when the owners and admins were told instead, once when nobody
    could be told and only a person can change that. See
    apps.vulnerabilities.notifications.notify_sla_violation.
    """
    try:
        now = timezone.now()

        # Find overdue vulnerabilities
        overdue_vulns = Vulnerability.objects.filter(
            due_date__lt=now,
            status=VulnerabilityStatus.OPEN
        ).select_related('asset', 'assigned_to')

        notification_count = 0
        not_sent_count = 0
        # identity is asked once per team and assignee, not once per row.
        directory = TeamDirectory()
        for vuln in overdue_vulns:
            last_entry = VulnerabilityHistory.objects.filter(
                vulnerability=vuln,
                change_reason__icontains=SLA_HISTORY_MARKER,
            ).order_by('-timestamp', '-pk').first()
            # At most one notification a day, however often this runs.
            if last_entry is not None and last_entry.timestamp >= now - timedelta(hours=24):
                continue

            overdue_hours = (now - vuln.due_date).total_seconds() / 3600
            delivery = notify_sla_violation(
                vuln, overdue_hours, _sla_outcome_of(last_entry), directory
            )
            if delivery is None:
                # Nothing the history does not already say.
                continue
            outcome = sla_outcome(delivery)

            # The violation is recorded on the vulnerability either way, so
            # its team sees it, and whether anybody was told (#678).
            VulnerabilityHistory.objects.create(
                vulnerability=vuln,
                field_name='sla_status',
                old_value='on_time',
                new_value='violated',
                change_reason=f'{SLA_HISTORY_MARKER} {outcome} - {overdue_hours:.1f}h overdue'
            )
            if delivery.sent:
                notification_count += 1
            else:
                not_sent_count += 1
                logger.warning(
                    f"SLA violation of vulnerability {vuln.id}: notification {outcome}"
                )

        logger.info(
            f"Sent {notification_count} SLA violation notifications; "
            f"{not_sent_count} not sent"
        )
        return {
            'notifications_sent': notification_count,
            'notifications_not_sent': not_sent_count,
        }

    except Exception as exc:
        logger.error(f"Error checking SLA violations: {exc}")
        raise


@shared_task(bind=True, max_retries=3)
def enrich_vulnerability_with_threat_intel(self, vulnerability_id):
    """
    Enrich vulnerability with threat intelligence data
    
    Args:
        vulnerability_id: ID of vulnerability to enrich
    """
    try:
        vulnerability = Vulnerability.objects.get(id=vulnerability_id)
        
        if not vulnerability.cve_id:
            logger.warning(f"No CVE ID for vulnerability {vulnerability_id}")
            return {'error': 'No CVE ID'}
        
        # Integration with threat intelligence feeds
        threat_intel_urls = getattr(settings, 'THREAT_INTEL_URLS', [])
        
        for intel_url in threat_intel_urls:
            try:
                response = requests.get(
                    f"{intel_url}/cve/{vulnerability.cve_id}",
                    timeout=30,
                    headers={'User-Agent': 'Open-Security-Guardian/1.0'}
                )
                
                if response.status_code == 200:
                    threat_data = response.json()
                    
                    # Update threat level based on intelligence
                    if threat_data.get('active_exploitation'):
                        vulnerability.threat_level = 'active'
                    elif threat_data.get('exploit_available'):
                        vulnerability.threat_level = 'emerging'
                    
                    # Update exploitability score
                    if 'exploitability_score' in threat_data:
                        vulnerability.exploitability_score = threat_data['exploitability_score']
                    
                    # Store threat intelligence in metadata
                    if 'threat_intelligence' not in vulnerability.metadata:
                        vulnerability.metadata['threat_intelligence'] = {}
                    
                    vulnerability.metadata['threat_intelligence'].update({
                        'source': intel_url,
                        'updated_at': timezone.now().isoformat(),
                        'data': threat_data
                    })
                    
                    vulnerability.save()
                    
                    logger.info(f"Enriched vulnerability {vulnerability_id} with threat intelligence")
                    return {'enrichment_successful': True}
                    
            except requests.RequestException as e:
                logger.warning(f"Failed to fetch threat intel from {intel_url}: {e}")
                continue
        
        return {'enrichment_successful': False, 'reason': 'No threat intelligence sources available'}
        
    except Vulnerability.DoesNotExist:
        logger.error(f"Vulnerability {vulnerability_id} not found")
        return {'error': 'Vulnerability not found'}
    except Exception as exc:
        logger.error(f"Error enriching vulnerability with threat intel: {exc}")
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@shared_task
def cleanup_old_vulnerability_history():
    """
    Clean up old vulnerability history entries to prevent database bloat
    """
    try:
        cutoff_date = timezone.now() - timedelta(days=365)  # Keep 1 year of history
        
        deleted_count = VulnerabilityHistory.objects.filter(
            timestamp__lt=cutoff_date
        ).delete()[0]
        
        logger.info(f"Cleaned up {deleted_count} old vulnerability history entries")
        return {'deleted_count': deleted_count}
        
    except Exception as exc:
        logger.error(f"Error cleaning up vulnerability history: {exc}")
        raise
