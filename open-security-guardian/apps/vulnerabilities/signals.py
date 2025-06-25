"""
Vulnerability Management Signals

Django signals for vulnerability lifecycle events.
"""

from django.db.models.signals import post_save, pre_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.utils import timezone

from .models import Vulnerability, VulnerabilityHistory, VulnerabilityStatus
from .tasks import (
    notify_vulnerability_assignment, 
    enrich_vulnerability_with_threat_intel,
    scan_vulnerability_remediation
)


@receiver(pre_save, sender=Vulnerability)
def track_vulnerability_changes(sender, instance, **kwargs):
    """Track changes to vulnerability fields for history"""
    if instance.pk:  # Only for existing vulnerabilities
        try:
            old_instance = Vulnerability.objects.get(pk=instance.pk)
            
            # Track significant field changes
            fields_to_track = [
                'status', 'severity', 'priority', 'assigned_to', 
                'assignee_group', 'risk_score', 'cvss_v3_score'
            ]
            
            for field in fields_to_track:
                old_value = getattr(old_instance, field)
                new_value = getattr(instance, field)
                
                # Handle foreign key fields
                if field == 'assigned_to':
                    old_value = old_value.id if old_value else None
                    new_value = new_value.id if new_value else None
                
                if old_value != new_value:
                    # Store change for post_save signal
                    if not hasattr(instance, '_tracked_changes'):
                        instance._tracked_changes = []
                    
                    instance._tracked_changes.append({
                        'field_name': field,
                        'old_value': str(old_value) if old_value is not None else None,
                        'new_value': str(new_value) if new_value is not None else None
                    })
        
        except Vulnerability.DoesNotExist:
            # This is a new vulnerability
            pass


@receiver(post_save, sender=Vulnerability)
def handle_vulnerability_save(sender, instance, created, **kwargs):
    """Handle post-save actions for vulnerabilities"""
    
    if created:
        # New vulnerability created
        print(f"New vulnerability created: {instance.title}")
        
        # Enrich with threat intelligence if CVE is available
        if instance.cve_id:
            enrich_vulnerability_with_threat_intel.delay(instance.id)
        
        # Create initial history entry
        VulnerabilityHistory.objects.create(
            vulnerability=instance,
            field_name='status',
            old_value=None,
            new_value=instance.status,
            change_reason='Vulnerability created'
        )
    
    else:
        # Existing vulnerability updated
        
        # Process tracked changes
        if hasattr(instance, '_tracked_changes'):
            for change in instance._tracked_changes:
                VulnerabilityHistory.objects.create(
                    vulnerability=instance,
                    field_name=change['field_name'],
                    old_value=change['old_value'],
                    new_value=change['new_value'],
                    change_reason='Field updated'
                )
            
            # Clear tracked changes
            delattr(instance, '_tracked_changes')
        
        # Handle status changes
        if hasattr(instance, '_tracked_changes'):
            status_changes = [c for c in instance._tracked_changes if c['field_name'] == 'status']
            if status_changes:
                old_status = status_changes[0]['old_value']
                new_status = status_changes[0]['new_value']
                
                # If vulnerability was resolved, record resolution time
                if new_status == VulnerabilityStatus.RESOLVED and old_status != VulnerabilityStatus.RESOLVED:
                    instance.resolved_at = timezone.now()
                    instance.save(update_fields=['resolved_at'])
                
                # If vulnerability was reopened, clear resolution time
                elif new_status != VulnerabilityStatus.RESOLVED and old_status == VulnerabilityStatus.RESOLVED:
                    instance.resolved_at = None
                    instance.save(update_fields=['resolved_at'])
        
        # Handle assignment changes
        if hasattr(instance, '_tracked_changes'):
            assignment_changes = [c for c in instance._tracked_changes 
                                if c['field_name'] in ['assigned_to', 'assignee_group']]
            if assignment_changes:
                # Send notification for new assignments
                assigned_to_changes = [c for c in assignment_changes if c['field_name'] == 'assigned_to']
                if assigned_to_changes and assigned_to_changes[0]['new_value']:
                    # Get the user who made the change (would need to be passed in context)
                    # For now, we'll skip the user context
                    notify_vulnerability_assignment.delay(instance.id, None)


@receiver(post_delete, sender=Vulnerability)
def handle_vulnerability_deletion(sender, instance, **kwargs):
    """Handle vulnerability deletion"""
    print(f"Vulnerability deleted: {instance.title}")
    
    # Create a final history entry (if history is preserved)
    # Note: This won't work as the vulnerability is deleted
    # Consider keeping vulnerability history in a separate table for audit purposes


# Additional signal handlers for related models

@receiver(post_save, sender=VulnerabilityHistory)
def log_vulnerability_history(sender, instance, created, **kwargs):
    """Log vulnerability history changes"""
    if created:
        print(f"Vulnerability history created: {instance.vulnerability.title} - {instance.field_name} changed from {instance.old_value} to {instance.new_value}")


# Integration signals for external systems

def trigger_external_integrations(vulnerability_id, event_type, **kwargs):
    """
    Trigger external system integrations
    
    Args:
        vulnerability_id: ID of the vulnerability
        event_type: Type of event (created, updated, assigned, closed, etc.)
        **kwargs: Additional event data
    """
    # This would integrate with external systems like:
    # - JIRA for ticket creation
    # - ServiceNow for workflow automation
    # - SIEM for security event correlation
    # - Slack/Teams for notifications
    
    # Example integrations:
    if event_type == 'high_risk_created':
        # Create JIRA ticket for high-risk vulnerabilities
        pass
    
    elif event_type == 'sla_violation':
        # Send urgent notifications
        pass
    
    elif event_type == 'mass_exploitation_detected':
        # Trigger emergency response
        pass


# Custom signal for risk score changes
from django.dispatch import Signal

vulnerability_risk_changed = Signal()

@receiver(vulnerability_risk_changed)
def handle_risk_score_change(sender, vulnerability, old_risk_score, new_risk_score, **kwargs):
    """Handle significant risk score changes"""
    risk_change = abs(new_risk_score - old_risk_score)
    
    if risk_change > 2.0:  # Significant risk change threshold
        print(f"Significant risk change for {vulnerability.title}: {old_risk_score:.1f} -> {new_risk_score:.1f}")
        
        # Trigger re-prioritization
        if new_risk_score >= 8.0 and old_risk_score < 8.0:
            # Escalate to high priority
            vulnerability.priority = 'p1' if new_risk_score >= 9.0 else 'p2'
            vulnerability.save(update_fields=['priority'])
        
        # Trigger external integrations
        trigger_external_integrations(
            vulnerability.id, 
            'risk_score_changed',
            old_score=old_risk_score,
            new_score=new_risk_score
        )
