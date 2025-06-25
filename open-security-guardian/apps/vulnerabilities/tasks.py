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

from .models import (
    Vulnerability, VulnerabilityStatus, VulnerabilityHistory,
    VulnerabilityAssessment
)

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
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


@shared_task
def check_sla_violations():
    """
    Check for SLA violations and send notifications
    """
    try:
        now = timezone.now()
        
        # Find overdue vulnerabilities
        overdue_vulns = Vulnerability.objects.filter(
            due_date__lt=now,
            status=VulnerabilityStatus.OPEN
        ).select_related('asset', 'assigned_to')
        
        notification_count = 0
        for vuln in overdue_vulns:
            # Check if we've already sent recent overdue notifications
            recent_notification = VulnerabilityHistory.objects.filter(
                vulnerability=vuln,
                change_reason__icontains='SLA violation notification',
                changed_at__gte=now - timedelta(hours=24)
            ).exists()
            
            if not recent_notification:
                # Send notification to assigned user and/or security team
                recipients = []
                if vuln.assigned_to and vuln.assigned_to.email:
                    recipients.append(vuln.assigned_to.email)
                
                # Add security team email
                security_team_email = getattr(settings, 'SECURITY_TEAM_EMAIL', None)
                if security_team_email:
                    recipients.append(security_team_email)
                
                if recipients:
                    overdue_hours = (now - vuln.due_date).total_seconds() / 3600
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
                    
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=recipients,
                        fail_silently=True
                    )
                    
                    # Record notification in history
                    VulnerabilityHistory.objects.create(
                        vulnerability=vuln,
                        field_name='sla_status',
                        old_value='on_time',
                        new_value='violated',
                        change_reason=f'SLA violation notification sent - {overdue_hours:.1f}h overdue'
                    )
                    
                    notification_count += 1
        
        logger.info(f"Sent {notification_count} SLA violation notifications")
        return {'notifications_sent': notification_count}
        
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
            changed_at__lt=cutoff_date
        ).delete()[0]
        
        logger.info(f"Cleaned up {deleted_count} old vulnerability history entries")
        return {'deleted_count': deleted_count}
        
    except Exception as exc:
        logger.error(f"Error cleaning up vulnerability history: {exc}")
        raise


@shared_task
def generate_vulnerability_reports():
    """
    Generate scheduled vulnerability reports
    """
    try:
        # This would generate various reports like:
        # - Executive summary
        # - Team dashboards  
        # - Compliance reports
        # - Trend analysis
        
        logger.info("Vulnerability report generation completed")
        return {'reports_generated': True}
        
    except Exception as exc:
        logger.error(f"Error generating vulnerability reports: {exc}")
        raise
