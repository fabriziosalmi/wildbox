"""
External System Integration Models

Models for managing integrations with external systems like JIRA, ServiceNow, SIEM, etc.
"""

from django.db import models
from django.contrib.auth.models import User
from django.core.validators import URLValidator
from django.utils import timezone
import uuid
import json


class IntegrationType(models.TextChoices):
    """Types of external integrations"""
    TICKETING = 'ticketing', 'Ticketing System'
    SIEM = 'siem', 'SIEM/SOAR'
    NOTIFICATION = 'notification', 'Notification System'
    CMDB = 'cmdb', 'Configuration Management'
    MONITORING = 'monitoring', 'Monitoring System'
    THREAT_INTEL = 'threat_intel', 'Threat Intelligence'
    SCANNING = 'scanning', 'Vulnerability Scanner'
    COMPLIANCE = 'compliance', 'Compliance System'
    ORCHESTRATION = 'orchestration', 'Security Orchestration'


class IntegrationStatus(models.TextChoices):
    """Integration operational status"""
    ACTIVE = 'active', 'Active'
    INACTIVE = 'inactive', 'Inactive'
    ERROR = 'error', 'Error'
    TESTING = 'testing', 'Testing'
    MAINTENANCE = 'maintenance', 'Maintenance'


class ExternalSystem(models.Model):
    """External system configuration and connection details"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Basic Information
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    system_type = models.CharField(max_length=20, choices=IntegrationType.choices)
    vendor = models.CharField(max_length=100, blank=True, help_text="System vendor/provider")
    version = models.CharField(max_length=50, blank=True)
    
    # Connection Details
    base_url = models.URLField(validators=[URLValidator()])
    api_endpoint = models.CharField(max_length=200, blank=True, help_text="API endpoint path")
    
    # Authentication
    auth_type = models.CharField(max_length=20, choices=[
        ('api_key', 'API Key'),
        ('oauth2', 'OAuth 2.0'),
        ('basic', 'Basic Auth'),
        ('bearer', 'Bearer Token'),
        ('custom', 'Custom Auth')
    ], default='api_key')
    
    auth_config = models.JSONField(default=dict, blank=True, help_text="Authentication configuration")
    
    # Connection Settings
    verify_ssl = models.BooleanField(default=True)
    timeout_seconds = models.PositiveIntegerField(default=30)
    retry_attempts = models.PositiveIntegerField(default=3)
    rate_limit_per_minute = models.PositiveIntegerField(null=True, blank=True)
    
    # Status and Health
    status = models.CharField(max_length=20, choices=IntegrationStatus.choices, default=IntegrationStatus.INACTIVE)
    last_health_check = models.DateTimeField(null=True, blank=True)
    last_sync = models.DateTimeField(null=True, blank=True)
    health_check_interval = models.PositiveIntegerField(default=300, help_text="Health check interval in seconds")
    
    # Capabilities and Features
    supports_bidirectional_sync = models.BooleanField(default=False)
    supports_webhooks = models.BooleanField(default=False)
    supports_real_time = models.BooleanField(default=False)
    
    # Configuration
    field_mappings = models.JSONField(default=dict, blank=True, help_text="Field mapping configuration")
    sync_filters = models.JSONField(default=dict, blank=True, help_text="Data sync filters")
    
    # Statistics
    total_requests = models.PositiveIntegerField(default=0)
    successful_requests = models.PositiveIntegerField(default=0)
    failed_requests = models.PositiveIntegerField(default=0)
    avg_response_time_ms = models.FloatField(default=0.0)
    
    # Metadata
    tags = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['system_type']),
            models.Index(fields=['status']),
            models.Index(fields=['last_health_check']),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_system_type_display()})"

    @property
    def is_healthy(self):
        """Check if system is healthy based on last health check"""
        if not self.last_health_check:
            return False
        
        threshold = timezone.now() - timezone.timedelta(seconds=self.health_check_interval * 2)
        return self.last_health_check > threshold and self.status == IntegrationStatus.ACTIVE

    @property
    def success_rate(self):
        """Calculate request success rate"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100

    def get_auth_headers(self):
        """Get authentication headers for API requests"""
        headers = {}
        
        if self.auth_type == 'api_key':
            api_key = self.auth_config.get('api_key')
            key_header = self.auth_config.get('key_header', 'X-API-Key')
            if api_key:
                headers[key_header] = api_key
        
        elif self.auth_type == 'bearer':
            token = self.auth_config.get('token')
            if token:
                headers['Authorization'] = f'Bearer {token}'
        
        elif self.auth_type == 'basic':
            username = self.auth_config.get('username')
            password = self.auth_config.get('password')
            if username and password:
                import base64
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers['Authorization'] = f'Basic {credentials}'
        
        return headers


class IntegrationMapping(models.Model):
    """Field and data mappings between Guardian and external systems"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    system = models.ForeignKey(ExternalSystem, on_delete=models.CASCADE, related_name='mappings')
    
    # Mapping Configuration
    guardian_entity = models.CharField(max_length=50, choices=[
        ('vulnerability', 'Vulnerability'),
        ('asset', 'Asset'),
        ('remediation', 'Remediation'),
        ('scan', 'Scan'),
        ('user', 'User')
    ])
    
    external_entity = models.CharField(max_length=100, help_text="External system entity name")
    
    # Field Mappings
    field_mappings = models.JSONField(default=dict, help_text="Guardian field -> External field mappings")
    value_transformations = models.JSONField(default=dict, blank=True, help_text="Value transformation rules")
    
    # Sync Configuration
    sync_direction = models.CharField(max_length=20, choices=[
        ('guardian_to_external', 'Guardian → External'),
        ('external_to_guardian', 'External → Guardian'),
        ('bidirectional', 'Bidirectional')
    ], default='guardian_to_external')
    
    auto_sync = models.BooleanField(default=True)
    sync_frequency = models.PositiveIntegerField(default=300, help_text="Sync frequency in seconds")
    
    # Filters and Conditions
    sync_conditions = models.JSONField(default=dict, blank=True, help_text="Conditions for syncing records")
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['system', 'guardian_entity']
        unique_together = ['system', 'guardian_entity', 'external_entity']

    def __str__(self):
        return f"{self.system.name}: {self.guardian_entity} → {self.external_entity}"


class SyncRecord(models.Model):
    """Track synchronization between Guardian and external systems"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Sync Configuration
    system = models.ForeignKey(ExternalSystem, on_delete=models.CASCADE, related_name='sync_records')
    mapping = models.ForeignKey(IntegrationMapping, on_delete=models.CASCADE, related_name='sync_records')
    
    # Record References
    guardian_record_id = models.UUIDField(help_text="Guardian record UUID")
    external_record_id = models.CharField(max_length=200, help_text="External system record ID")
    
    # Sync Status
    sync_status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('conflict', 'Conflict'),
        ('skipped', 'Skipped')
    ], default='pending')
    
    # Sync Direction for this record
    last_sync_direction = models.CharField(max_length=20, choices=[
        ('guardian_to_external', 'Guardian → External'),
        ('external_to_guardian', 'External → Guardian')
    ])
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True)
    last_sync_at = models.DateTimeField(auto_now=True)
    next_sync_at = models.DateTimeField(null=True, blank=True)
    
    # Sync Details
    sync_attempts = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)
    conflict_details = models.JSONField(default=dict, blank=True)
    
    # Change Tracking
    guardian_last_modified = models.DateTimeField(null=True, blank=True)
    external_last_modified = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    sync_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-last_sync_at']
        indexes = [
            models.Index(fields=['system', 'sync_status']),
            models.Index(fields=['guardian_record_id']),
            models.Index(fields=['external_record_id']),
            models.Index(fields=['next_sync_at']),
        ]
        unique_together = ['system', 'guardian_record_id', 'mapping']

    def __str__(self):
        return f"Sync: {self.guardian_record_id} ↔ {self.external_record_id}"

    def mark_success(self, direction, metadata=None):
        """Mark sync as successful"""
        self.sync_status = 'success'
        self.last_sync_direction = direction
        self.last_sync_at = timezone.now()
        if metadata:
            self.sync_metadata.update(metadata)
        self.save()

    def mark_failed(self, error_message, metadata=None):
        """Mark sync as failed"""
        self.sync_status = 'failed'
        self.error_message = error_message
        self.sync_attempts += 1
        if metadata:
            self.sync_metadata.update(metadata)
        self.save()


class WebhookEndpoint(models.Model):
    """Webhook endpoints for real-time integration"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    system = models.ForeignKey(ExternalSystem, on_delete=models.CASCADE, related_name='webhooks')
    
    # Webhook Configuration
    name = models.CharField(max_length=200)
    endpoint_url = models.CharField(max_length=500, unique=True, help_text="Webhook endpoint path")
    secret_token = models.CharField(max_length=200, blank=True, help_text="Webhook verification token")
    
    # Event Configuration
    event_types = models.JSONField(default=list, help_text="List of event types to trigger webhook")
    filters = models.JSONField(default=dict, blank=True, help_text="Event filters")
    
    # Security
    verify_signature = models.BooleanField(default=True)
    allowed_ips = models.JSONField(default=list, blank=True, help_text="Allowed source IP addresses")
    
    # Status
    is_active = models.BooleanField(default=True)
    last_triggered = models.DateTimeField(null=True, blank=True)
    total_requests = models.PositiveIntegerField(default=0)
    successful_requests = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"Webhook: {self.name} ({self.system.name})"


class IntegrationLog(models.Model):
    """Logging for integration activities"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    system = models.ForeignKey(ExternalSystem, on_delete=models.CASCADE, related_name='logs')
    
    # Log Details
    operation = models.CharField(max_length=50, choices=[
        ('sync', 'Data Sync'),
        ('webhook', 'Webhook'),
        ('health_check', 'Health Check'),
        ('auth', 'Authentication'),
        ('api_call', 'API Call'),
        ('error', 'Error'),
        ('config_change', 'Configuration Change')
    ])
    
    level = models.CharField(max_length=10, choices=[
        ('debug', 'Debug'),
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical')
    ], default='info')
    
    message = models.TextField()
    details = models.JSONField(default=dict, blank=True)
    
    # Context
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    record_id = models.UUIDField(null=True, blank=True, help_text="Related Guardian record ID")
    external_id = models.CharField(max_length=200, blank=True, help_text="Related external record ID")
    
    # Request/Response
    request_data = models.JSONField(default=dict, blank=True)
    response_data = models.JSONField(default=dict, blank=True)
    response_time_ms = models.PositiveIntegerField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['system', 'operation']),
            models.Index(fields=['level']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return f"{self.system.name}: {self.operation} ({self.level})"


class NotificationChannel(models.Model):
    """Notification channels for alerts and updates"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Channel Information
    name = models.CharField(max_length=200)
    channel_type = models.CharField(max_length=20, choices=[
        ('email', 'Email'),
        ('slack', 'Slack'),
        ('teams', 'Microsoft Teams'),
        ('webhook', 'Generic Webhook'),
        ('sms', 'SMS'),
        ('push', 'Push Notification')
    ])
    
    # Configuration
    config = models.JSONField(default=dict, help_text="Channel-specific configuration")
    
    # Event Subscriptions
    event_types = models.JSONField(default=list, help_text="Subscribed event types")
    severity_filter = models.JSONField(default=list, blank=True, help_text="Severity levels to notify")
    
    # Recipients
    recipients = models.JSONField(default=list, help_text="Notification recipients")
    
    # Status
    is_active = models.BooleanField(default=True)
    last_notification = models.DateTimeField(null=True, blank=True)
    total_notifications = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.get_channel_type_display()})"

    def send_notification(self, event_type, message, severity='info', metadata=None):
        """Send notification through this channel"""
        # This would contain the actual notification sending logic
        # Implementation would depend on the channel type
        
        if not self.is_active:
            return False
        
        if event_type not in self.event_types:
            return False
        
        if self.severity_filter and severity not in self.severity_filter:
            return False
        
        # Channel-specific sending logic would go here
        # For now, just update counters
        self.total_notifications += 1
        self.last_notification = timezone.now()
        self.save(update_fields=['total_notifications', 'last_notification'])
        
        return True


class ApiUsageMetrics(models.Model):
    """Track API usage metrics for external systems"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    system = models.ForeignKey(ExternalSystem, on_delete=models.CASCADE, related_name='usage_metrics')
    
    # Time Period
    date = models.DateField()
    hour = models.PositiveIntegerField(null=True, blank=True, help_text="Hour of day (0-23) for hourly metrics")
    
    # Request Metrics
    total_requests = models.PositiveIntegerField(default=0)
    successful_requests = models.PositiveIntegerField(default=0)
    failed_requests = models.PositiveIntegerField(default=0)
    
    # Performance Metrics
    avg_response_time_ms = models.FloatField(default=0.0)
    min_response_time_ms = models.PositiveIntegerField(default=0)
    max_response_time_ms = models.PositiveIntegerField(default=0)
    
    # Data Volume
    bytes_sent = models.PositiveBigIntegerField(default=0)
    bytes_received = models.PositiveBigIntegerField(default=0)
    
    # Error Breakdown
    auth_errors = models.PositiveIntegerField(default=0)
    rate_limit_errors = models.PositiveIntegerField(default=0)
    timeout_errors = models.PositiveIntegerField(default=0)
    server_errors = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-date', '-hour']
        indexes = [
            models.Index(fields=['system', 'date']),
            models.Index(fields=['date', 'hour']),
        ]
        unique_together = ['system', 'date', 'hour']

    def __str__(self):
        hour_str = f" {self.hour}:00" if self.hour is not None else ""
        return f"{self.system.name} metrics - {self.date}{hour_str}"
