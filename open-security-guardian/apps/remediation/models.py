"""
Remediation Management Models

Models for vulnerability remediation workflow, ticketing, and tracking.
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import URLValidator
import uuid
import json


class RemediationStatus(models.TextChoices):
    """Remediation workflow status"""
    PENDING = 'pending', 'Pending'
    ASSIGNED = 'assigned', 'Assigned'
    IN_PROGRESS = 'in_progress', 'In Progress'
    TESTING = 'testing', 'Testing'
    COMPLETED = 'completed', 'Completed'
    VERIFIED = 'verified', 'Verified'
    REJECTED = 'rejected', 'Rejected'
    DEFERRED = 'deferred', 'Deferred'


class RemediationPriority(models.TextChoices):
    """Remediation priority levels"""
    EMERGENCY = 'emergency', 'Emergency (P0)'
    HIGH = 'high', 'High (P1)'
    MEDIUM = 'medium', 'Medium (P2)'
    LOW = 'low', 'Low (P3)'
    PLANNED = 'planned', 'Planned (P4)'


class TicketingSystem(models.TextChoices):
    """Supported ticketing systems"""
    JIRA = 'jira', 'Jira'
    SERVICENOW = 'servicenow', 'ServiceNow'
    GITHUB = 'github', 'GitHub Issues'
    GITLAB = 'gitlab', 'GitLab Issues'
    AZURE_DEVOPS = 'azure_devops', 'Azure DevOps'
    CUSTOM = 'custom', 'Custom System'


class RemediationTicket(models.Model):
    """External ticket integration for remediation tracking"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Basic Information
    title = models.CharField(max_length=500)
    description = models.TextField()
    
    # Ticketing System Integration
    system = models.CharField(max_length=20, choices=TicketingSystem.choices)
    external_ticket_id = models.CharField(max_length=100, help_text="Ticket ID in external system")
    external_url = models.URLField(blank=True, validators=[URLValidator()])
    
    # Priority and Status
    priority = models.CharField(max_length=20, choices=RemediationPriority.choices)
    status = models.CharField(max_length=20, choices=RemediationStatus.choices, default=RemediationStatus.PENDING)
    
    # Assignment
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_tickets')
    assigned_team = models.CharField(max_length=100, blank=True, help_text="External team assignment")
    
    # Timing and SLA
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    due_date = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Integration Metadata
    system_metadata = models.JSONField(default=dict, blank=True, help_text="System-specific metadata")
    sync_enabled = models.BooleanField(default=True, help_text="Enable bidirectional sync")
    last_sync = models.DateTimeField(null=True, blank=True)
    
    # Creator and modifier tracking
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_tickets')

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['system', 'external_ticket_id']),
            models.Index(fields=['status']),
            models.Index(fields=['priority']),
            models.Index(fields=['due_date']),
        ]
        unique_together = ['system', 'external_ticket_id']

    def __str__(self):
        return f"{self.system.upper()}-{self.external_ticket_id}: {self.title}"

    @property
    def is_overdue(self):
        """Check if ticket is overdue"""
        return (
            self.due_date and 
            timezone.now() > self.due_date and 
            self.status not in [RemediationStatus.COMPLETED, RemediationStatus.VERIFIED]
        )

    @property
    def days_until_due(self):
        """Calculate days until due date"""
        if not self.due_date:
            return None
        delta = self.due_date - timezone.now()
        return delta.days


class RemediationWorkflow(models.Model):
    """Main remediation workflow management"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Associated Vulnerability
    vulnerability = models.OneToOneField('vulnerabilities.Vulnerability', on_delete=models.CASCADE, related_name='remediation')
    
    # Workflow Information
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    remediation_type = models.CharField(max_length=50, choices=[
        ('patch', 'Software Patch'),
        ('configuration', 'Configuration Change'),
        ('workaround', 'Workaround Implementation'),
        ('upgrade', 'System Upgrade'),
        ('replacement', 'Component Replacement'),
        ('mitigation', 'Risk Mitigation'),
        ('acceptance', 'Risk Acceptance'),
        ('other', 'Other')
    ])
    
    # Status and Priority
    status = models.CharField(max_length=20, choices=RemediationStatus.choices, default=RemediationStatus.PENDING)
    priority = models.CharField(max_length=20, choices=RemediationPriority.choices)
    
    # Assignment and Ownership
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_remediations')
    assigned_team = models.CharField(max_length=100, blank=True)
    approver = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approving_remediations')
    
    # External Ticket Integration
    ticket = models.ForeignKey(RemediationTicket, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Timing and SLA
    estimated_effort_hours = models.FloatField(null=True, blank=True)
    actual_effort_hours = models.FloatField(null=True, blank=True)
    
    planned_start_date = models.DateTimeField(null=True, blank=True)
    actual_start_date = models.DateTimeField(null=True, blank=True)
    planned_completion_date = models.DateTimeField(null=True, blank=True)
    actual_completion_date = models.DateTimeField(null=True, blank=True)
    
    # Remediation Details
    remediation_steps = models.JSONField(default=list, blank=True, help_text="List of remediation steps")
    rollback_plan = models.TextField(blank=True, help_text="Rollback procedures if needed")
    testing_plan = models.TextField(blank=True, help_text="Testing and validation plan")
    
    # Business Impact
    business_justification = models.TextField(blank=True)
    maintenance_window_required = models.BooleanField(default=False)
    downtime_expected_minutes = models.PositiveIntegerField(null=True, blank=True)
    affected_systems = models.JSONField(default=list, blank=True)
    
    # Dependencies
    blocking_issues = models.ManyToManyField('self', blank=True, symmetrical=False, related_name='blocked_by')
    prerequisite_tasks = models.TextField(blank=True)
    
    # Progress Tracking
    progress_percentage = models.FloatField(default=0.0, help_text="0-100 completion percentage")
    current_step = models.CharField(max_length=200, blank=True)
    
    # Risk Assessment
    implementation_risk = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ], default='medium')
    
    risk_mitigation_notes = models.TextField(blank=True)
    
    # Metadata
    tags = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    # Tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_remediations')

    class Meta:
        ordering = ['-priority', '-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['priority']),
            models.Index(fields=['assigned_to']),
            models.Index(fields=['planned_completion_date']),
            models.Index(fields=['vulnerability']),
        ]

    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"

    @property
    def is_overdue(self):
        """Check if remediation is overdue"""
        return (
            self.planned_completion_date and 
            timezone.now() > self.planned_completion_date and 
            self.status not in [RemediationStatus.COMPLETED, RemediationStatus.VERIFIED]
        )

    @property
    def duration_days(self):
        """Calculate actual duration in days"""
        if self.actual_start_date and self.actual_completion_date:
            return (self.actual_completion_date - self.actual_start_date).days
        return None

    def calculate_sla_status(self):
        """Calculate SLA compliance status"""
        if not self.planned_completion_date:
            return 'no_sla'
        
        now = timezone.now()
        if self.status in [RemediationStatus.COMPLETED, RemediationStatus.VERIFIED]:
            completion_date = self.actual_completion_date or now
            return 'met' if completion_date <= self.planned_completion_date else 'missed'
        else:
            return 'at_risk' if now > self.planned_completion_date else 'on_track'

    def update_progress(self, percentage, current_step=None):
        """Update remediation progress"""
        self.progress_percentage = max(0, min(100, percentage))
        if current_step:
            self.current_step = current_step
        
        # Auto-update status based on progress
        if percentage >= 100 and self.status == RemediationStatus.IN_PROGRESS:
            self.status = RemediationStatus.TESTING
        elif percentage > 0 and self.status == RemediationStatus.ASSIGNED:
            self.status = RemediationStatus.IN_PROGRESS
            self.actual_start_date = timezone.now()
        
        self.save()


class RemediationStep(models.Model):
    """Individual steps in a remediation workflow"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    workflow = models.ForeignKey(RemediationWorkflow, on_delete=models.CASCADE, related_name='steps')
    
    # Step Information
    title = models.CharField(max_length=200)
    description = models.TextField()
    order = models.PositiveIntegerField(help_text="Step execution order")
    
    # Status and Assignment
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('skipped', 'Skipped')
    ], default='pending')
    
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Timing
    estimated_duration_minutes = models.PositiveIntegerField(null=True, blank=True)
    actual_duration_minutes = models.PositiveIntegerField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Step Details
    instructions = models.TextField(help_text="Detailed step instructions")
    validation_criteria = models.TextField(blank=True, help_text="How to validate step completion")
    automation_script = models.TextField(blank=True, help_text="Optional automation script")
    
    # Results
    execution_notes = models.TextField(blank=True)
    validation_results = models.TextField(blank=True)
    attachments = models.JSONField(default=list, blank=True, help_text="File attachments")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['workflow', 'order']
        unique_together = ['workflow', 'order']

    def __str__(self):
        return f"Step {self.order}: {self.title}"

    def start_execution(self, user):
        """Mark step as started"""
        self.status = 'in_progress'
        self.started_at = timezone.now()
        self.assigned_to = user
        self.save()

    def complete_execution(self, notes=None, validation_results=None):
        """Mark step as completed"""
        self.status = 'completed'
        self.completed_at = timezone.now()
        if notes:
            self.execution_notes = notes
        if validation_results:
            self.validation_results = validation_results
        
        if self.started_at:
            duration = timezone.now() - self.started_at
            self.actual_duration_minutes = int(duration.total_seconds() / 60)
        
        self.save()
        
        # Update parent workflow progress
        self.workflow.update_workflow_progress()


class RemediationComment(models.Model):
    """Comments and updates on remediation workflows"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    workflow = models.ForeignKey(RemediationWorkflow, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    
    content = models.TextField()
    comment_type = models.CharField(max_length=20, choices=[
        ('general', 'General Comment'),
        ('status_update', 'Status Update'),
        ('issue', 'Issue/Problem'),
        ('resolution', 'Resolution'),
        ('approval', 'Approval'),
        ('rejection', 'Rejection')
    ], default='general')
    
    # Metadata
    is_internal = models.BooleanField(default=False, help_text="Internal comment, not synced to external systems")
    attachments = models.JSONField(default=list, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Comment by {self.author.username} on {self.workflow.title}"


class RemediationTemplate(models.Model):
    """Templates for common remediation workflows"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Template Information
    name = models.CharField(max_length=200)
    description = models.TextField()
    category = models.CharField(max_length=100, help_text="Remediation category")
    
    # Template Configuration
    remediation_type = models.CharField(max_length=50, choices=[
        ('patch', 'Software Patch'),
        ('configuration', 'Configuration Change'),
        ('workaround', 'Workaround Implementation'),
        ('upgrade', 'System Upgrade'),
        ('replacement', 'Component Replacement'),
        ('mitigation', 'Risk Mitigation'),
        ('other', 'Other')
    ])
    
    # Default Settings
    default_priority = models.CharField(max_length=20, choices=RemediationPriority.choices, default='medium')
    estimated_effort_hours = models.FloatField(null=True, blank=True)
    
    # Template Content
    step_templates = models.JSONField(default=list, help_text="Template steps for the workflow")
    rollback_template = models.TextField(blank=True)
    testing_template = models.TextField(blank=True)
    
    # Usage Tracking
    usage_count = models.PositiveIntegerField(default=0)
    success_rate = models.FloatField(default=0.0, help_text="Success rate percentage")
    
    # Applicability
    vulnerability_types = models.JSONField(default=list, blank=True, help_text="Applicable vulnerability types")
    asset_types = models.JSONField(default=list, blank=True, help_text="Applicable asset types")
    
    # Metadata
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['category', 'name']

    def __str__(self):
        return f"{self.name} ({self.category})"

    def apply_to_workflow(self, workflow):
        """Apply template to a remediation workflow"""
        workflow.remediation_type = self.remediation_type
        workflow.estimated_effort_hours = self.estimated_effort_hours
        workflow.rollback_plan = self.rollback_template
        workflow.testing_plan = self.testing_template
        workflow.save()
        
        # Create steps from template
        for i, step_template in enumerate(self.step_templates, 1):
            RemediationStep.objects.create(
                workflow=workflow,
                title=step_template.get('title', f'Step {i}'),
                description=step_template.get('description', ''),
                order=i,
                instructions=step_template.get('instructions', ''),
                validation_criteria=step_template.get('validation_criteria', ''),
                estimated_duration_minutes=step_template.get('estimated_duration_minutes'),
                automation_script=step_template.get('automation_script', '')
            )
        
        # Update usage count
        self.usage_count += 1
        self.save(update_fields=['usage_count'])


class RemediationMetrics(models.Model):
    """Metrics and KPIs for remediation performance"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Time Period
    date = models.DateField()
    period_type = models.CharField(max_length=20, choices=[
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly')
    ])
    
    # Volume Metrics
    remediations_created = models.PositiveIntegerField(default=0)
    remediations_completed = models.PositiveIntegerField(default=0)
    remediations_overdue = models.PositiveIntegerField(default=0)
    
    # Performance Metrics
    avg_completion_time_hours = models.FloatField(default=0.0)
    sla_compliance_rate = models.FloatField(default=0.0, help_text="Percentage")
    first_time_fix_rate = models.FloatField(default=0.0, help_text="Percentage")
    
    # Priority Breakdown
    emergency_completed = models.PositiveIntegerField(default=0)
    high_completed = models.PositiveIntegerField(default=0)
    medium_completed = models.PositiveIntegerField(default=0)
    low_completed = models.PositiveIntegerField(default=0)
    
    # Team Performance
    team_metrics = models.JSONField(default=dict, blank=True, help_text="Per-team performance data")
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-date']
        unique_together = ['date', 'period_type']

    def __str__(self):
        return f"Remediation Metrics - {self.date} ({self.period_type})"
