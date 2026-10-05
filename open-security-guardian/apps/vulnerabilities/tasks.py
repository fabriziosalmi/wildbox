"""
Vulnerability Management Tasks

Celery tasks for background processing of vulnerability data.
"""

from celery import shared_task
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
import logging
import requests
from datetime import timedelta

from apps.core.locks import single_instance
from apps.core.tenancy import is_current_member

from .models import (
    Vulnerability, VulnerabilityStatus, VulnerabilityHistory,
    VulnerabilityAssessment
)

logger = logging.getLogger(__name__)


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
    Send notification when vulnerability is assigned
    
    Args:
        vulnerability_id: ID of the assigned vulnerability
        assigned_by_user_id: ID of user who made the assignment
    """
    try:
        vulnerability = Vulnerability.objects.get(id=vulnerability_id)
        assigned_by = User.objects.get(id=assigned_by_user_id)

        if vulnerability.assigned_to and member_assignee(vulnerability) is None:
            # Assigned to somebody who is not, or no longer, a member of the
            # vulnerability's team: the API refuses that, so this is a stale
            # assignment. Nothing about the team's data is e-mailed (#676).
            logger.warning(
                f"Assignment notification for vulnerability {vulnerability_id} not sent: "
                "the assignee is not a member of its team"
            )
            return {'notification_sent': False}

        if vulnerability.assigned_to:
            recipient_email = vulnerability.assigned_to.email
            recipient_name = vulnerability.assigned_to.get_full_name()
        else:
            # Handle group assignment - would need group email mapping
            logger.warning(f"Group assignment notification not implemented for {vulnerability.assignee_group}")
            return
        
        if not recipient_email:
            logger.warning(f"No email address for assigned user {vulnerability.assigned_to.username}")
            return
        
        subject = f"Vulnerability Assigned: {vulnerability.title}"
        message = f"""
        Hello {recipient_name},
        
        A vulnerability has been assigned to you:
        
        Title: {vulnerability.title}
        Asset: {vulnerability.asset.name}
        Severity: {vulnerability.get_severity_display()}
        Risk Score: {vulnerability.risk_score:.1f}
        Due Date: {vulnerability.due_date.strftime('%Y-%m-%d %H:%M') if vulnerability.due_date else 'Not set'}
        
        Assigned by: {assigned_by.get_full_name()}
        
        Please review and take appropriate action.
        
        View vulnerability: {settings.BASE_URL}/vulnerabilities/{vulnerability.id}/
        
        Best regards,
        Security Team
        """
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient_email],
            fail_silently=False
        )
        
        logger.info(f"Assignment notification sent for vulnerability {vulnerability_id}")
        return {'notification_sent': True}
        
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
SLA_NO_RECIPIENT = 'not sent (no assignee to e-mail)'


def sla_recipient(vulnerability):
    """Who is told that a vulnerability is past its due date: its assignee.

    Nobody else. The check also copied every violation to a
    SECURITY_TEAM_EMAIL setting, one address for the whole platform: defined,
    it would have received every team's asset names and vulnerability titles
    (#678). A vulnerability without an assignee, or whose assignee has no
    e-mail address, notifies nobody, and its history says so.

    The assignee is told only while they are a member of the
    vulnerability's team (#676). identity tells guardian when a member
    leaves, and their assignments are cleared then; if that notice never
    arrived, this is what keeps a team's asset names and vulnerability
    titles from being e-mailed to somebody who left it.
    """
    assignee = member_assignee(vulnerability)
    return (assignee.email or None) if assignee else None


def member_assignee(vulnerability):
    """The vulnerability's assignee, if they may be told about it, else None.

    A vulnerability of a team: its assignee, while a current member of that
    team. A vulnerability without a team (written before guardian kept one)
    has no team boundary to cross: its assignee, as before.
    """
    assignee = vulnerability.assigned_to
    if assignee is None:
        return None
    team_id = vulnerability.asset.team_id
    if team_id is not None and not is_current_member(assignee, team_id):
        return None
    return assignee


@shared_task
@single_instance
def check_sla_violations():
    """
    Record SLA violations and notify the assignee of each

    A violation is recorded in the vulnerability's history with whether its
    notification was sent: once a day while there is an assignee to remind,
    once when there is nobody to tell.
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
        for vuln in overdue_vulns:
            recipient = sla_recipient(vuln)
            last_entry = VulnerabilityHistory.objects.filter(
                vulnerability=vuln,
                change_reason__icontains=SLA_HISTORY_MARKER,
            ).order_by('-timestamp').first()
            if last_entry is not None:
                # At most one notification a day, however often this runs.
                if last_entry.timestamp >= now - timedelta(hours=24):
                    continue
                # Nobody to tell, and the history already says so: once is
                # enough, not a line a day for every unassigned vulnerability.
                if not recipient and SLA_NO_RECIPIENT in last_entry.change_reason:
                    continue

            overdue_hours = (now - vuln.due_date).total_seconds() / 3600
            sent = False
            if recipient:
                subject = f"SLA Violation: {vuln.title} - {overdue_hours:.1f}h overdue"
                message = f"""
                    SLA Violation Alert

                    Vulnerability: {vuln.title}
                    Asset: {vuln.asset.name}
                    Risk Score: {vuln.risk_score:.1f}
                    Due Date: {vuln.due_date.strftime('%Y-%m-%d %H:%M')}
                    Overdue by: {overdue_hours:.1f} hours

                    Please take immediate action.

                    View: {settings.BASE_URL}/vulnerabilities/{vuln.id}/
                    """
                # send_mail answers how many messages went out: with
                # fail_silently, 0 is a delivery that failed.
                sent = bool(send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[recipient],
                    fail_silently=True
                ))
                outcome = 'sent' if sent else 'not sent (delivery failed)'
            else:
                outcome = SLA_NO_RECIPIENT

            # The violation is recorded on the vulnerability either way, so
            # its team sees it, and whether anybody was told (#678).
            VulnerabilityHistory.objects.create(
                vulnerability=vuln,
                field_name='sla_status',
                old_value='on_time',
                new_value='violated',
                change_reason=f'{SLA_HISTORY_MARKER} {outcome} - {overdue_hours:.1f}h overdue'
            )
            if sent:
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
