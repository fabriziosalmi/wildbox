"""
Scanner Integration Models

Models for managing vulnerability scanners and their configurations.
"""

from django.db import models
from django.contrib.auth.models import User
from django.core.validators import URLValidator
from django.utils import timezone
import uuid
import json


class ScannerType(models.TextChoices):
    """Types of vulnerability scanners"""
    NESSUS = 'nessus', 'Nessus'
    QUALYS = 'qualys', 'Qualys'
    OPENVAS = 'openvas', 'OpenVAS'
    RAPID7 = 'rapid7', 'Rapid7 InsightVM'
    CUSTOM = 'custom', 'Custom Scanner'


class ScannerStatus(models.TextChoices):
    """Scanner operational status"""
    ACTIVE = 'active', 'Active'
    INACTIVE = 'inactive', 'Inactive'
    MAINTENANCE = 'maintenance', 'Maintenance'
    ERROR = 'error', 'Error'


class Scanner(models.Model):
    """Scanner configuration and management"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Basic Information
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    scanner_type = models.CharField(max_length=20, choices=ScannerType.choices)
    
    # Connection Details
    base_url = models.URLField(validators=[URLValidator()])
    api_key = models.CharField(max_length=500, blank=True, help_text="API key or token")
    username = models.CharField(max_length=100, blank=True)
    password = models.CharField(max_length=100, blank=True, help_text="Encrypted password")
    
    # Configuration
    verify_ssl = models.BooleanField(default=True)
    timeout_seconds = models.PositiveIntegerField(default=30)
    max_concurrent_scans = models.PositiveIntegerField(default=5)
    
    # Status and Health
    status = models.CharField(max_length=20, choices=ScannerStatus.choices, default=ScannerStatus.INACTIVE)
    last_health_check = models.DateTimeField(null=True, blank=True)
    health_check_interval = models.PositiveIntegerField(default=300, help_text="Health check interval in seconds")
    
    # Capabilities
    supports_authenticated_scans = models.BooleanField(default=False)
    supports_compliance_scans = models.BooleanField(default=False)
    supports_agent_scans = models.BooleanField(default=False)
    
    # Statistics
    total_scans_completed = models.PositiveIntegerField(default=0)
    total_vulnerabilities_found = models.PositiveIntegerField(default=0)
    avg_scan_duration_minutes = models.FloatField(default=0.0)
    
    # Metadata
    tags = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['scanner_type']),
            models.Index(fields=['status']),
            models.Index(fields=['last_health_check']),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_scanner_type_display()})"

    @property
    def is_healthy(self):
        """Check if scanner is healthy based on last health check"""
        if not self.last_health_check:
            return False
        
        threshold = timezone.now() - timezone.timedelta(seconds=self.health_check_interval * 2)
        return self.last_health_check > threshold and self.status == ScannerStatus.ACTIVE

    def get_connection_info(self):
        """Get connection information for API calls"""
        return {
            'base_url': self.base_url,
            'api_key': self.api_key,
            'username': self.username,
            'password': self.password,  # In real implementation, this should be decrypted
            'verify_ssl': self.verify_ssl,
            'timeout': self.timeout_seconds
        }


class ScanProfile(models.Model):
    """Scan configuration profiles"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    scanner = models.ForeignKey(Scanner, on_delete=models.CASCADE, related_name='profiles')
    
    # Scan Configuration
    scan_template_id = models.CharField(max_length=100, blank=True, help_text="Scanner-specific template ID")
    scan_policy_id = models.CharField(max_length=100, blank=True, help_text="Scanner-specific policy ID")
    
    # Scan Options
    enable_safe_checks = models.BooleanField(default=True)
    enable_web_app_tests = models.BooleanField(default=False)
    enable_compliance_checks = models.BooleanField(default=False)
    
    # Port and Service Configuration
    port_range = models.CharField(max_length=100, default="1-65535", help_text="Port range to scan")
    exclude_ports = models.CharField(max_length=200, blank=True, help_text="Ports to exclude")
    
    # Timing and Performance
    scan_speed = models.CharField(max_length=20, choices=[
        ('slow', 'Slow'),
        ('normal', 'Normal'),
        ('fast', 'Fast'),
        ('aggressive', 'Aggressive')
    ], default='normal')
    
    max_scan_duration_hours = models.PositiveIntegerField(default=24)
    
    # Advanced Configuration
    advanced_settings = models.JSONField(default=dict, blank=True)
    
    # Usage Statistics
    times_used = models.PositiveIntegerField(default=0)
    avg_scan_time_minutes = models.FloatField(default=0.0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['name']
        unique_together = ['scanner', 'name']

    def __str__(self):
        return f"{self.name} ({self.scanner.name})"


class ScanStatus(models.TextChoices):
    """Scan execution status"""
    PENDING = 'pending', 'Pending'
    RUNNING = 'running', 'Running'
    COMPLETED = 'completed', 'Completed'
    FAILED = 'failed', 'Failed'
    CANCELLED = 'cancelled', 'Cancelled'
    PAUSED = 'paused', 'Paused'


class Scan(models.Model):
    """Individual scan instances"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Basic Information
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    scanner = models.ForeignKey(Scanner, on_delete=models.CASCADE, related_name='scans')
    profile = models.ForeignKey(ScanProfile, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Targets
    target_assets = models.ManyToManyField('assets.Asset', related_name='scans')
    target_ranges = models.JSONField(default=list, blank=True, help_text="IP ranges and hostnames")
    
    # Scheduling
    scheduled_start = models.DateTimeField(null=True, blank=True)
    recurrence_pattern = models.CharField(max_length=100, blank=True, help_text="Cron-like schedule")
    
    # Execution Details
    status = models.CharField(max_length=20, choices=ScanStatus.choices, default=ScanStatus.PENDING)
    scanner_scan_id = models.CharField(max_length=100, blank=True, help_text="Scanner's native scan ID")
    
    # Timing
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.PositiveIntegerField(null=True, blank=True)
    
    # Results Summary
    total_hosts_scanned = models.PositiveIntegerField(default=0)
    total_vulnerabilities_found = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    info_count = models.PositiveIntegerField(default=0)
    
    # Progress Tracking
    progress_percentage = models.FloatField(default=0.0)
    current_host = models.CharField(max_length=200, blank=True)
    
    # Error Handling
    error_message = models.TextField(blank=True)
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=3)
    
    # Metadata
    scan_settings = models.JSONField(default=dict, blank=True)
    scan_metadata = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['scheduled_start']),
            models.Index(fields=['scanner', 'status']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return f"{self.name} - {self.get_status_display()}"

    @property
    def duration_formatted(self):
        """Get formatted duration string"""
        if not self.duration_seconds:
            return "N/A"
        
        hours = self.duration_seconds // 3600
        minutes = (self.duration_seconds % 3600) // 60
        seconds = self.duration_seconds % 60
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

    @property
    def is_active(self):
        """Check if scan is currently active"""
        return self.status in [ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.PAUSED]

    def calculate_risk_score(self):
        """Calculate overall risk score for scan results"""
        if self.total_vulnerabilities_found == 0:
            return 0.0
        
        # Weighted risk calculation
        risk_score = (
            self.critical_count * 10.0 +
            self.high_count * 7.5 +
            self.medium_count * 5.0 +
            self.low_count * 2.5 +
            self.info_count * 1.0
        ) / max(self.total_vulnerabilities_found, 1)
        
        return min(10.0, risk_score)


class ScanResult(models.Model):
    """Individual scan result/finding"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='results')
    asset = models.ForeignKey('assets.Asset', on_delete=models.CASCADE, null=True, blank=True)
    
    # Finding Details
    plugin_id = models.CharField(max_length=100)
    plugin_name = models.CharField(max_length=500)
    severity = models.CharField(max_length=20, choices=[
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info')
    ])
    
    # Vulnerability Information
    cve_ids = models.JSONField(default=list, blank=True)
    cvss_base_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=200, blank=True)
    
    # Location Information
    host = models.CharField(max_length=200)
    port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, blank=True)
    service = models.CharField(max_length=100, blank=True)
    
    # Finding Content
    description = models.TextField()
    solution = models.TextField(blank=True)
    proof = models.TextField(blank=True, help_text="Proof of concept or evidence")
    
    # References
    references = models.JSONField(default=list, blank=True)
    
    # Processing Status
    processed = models.BooleanField(default=False)
    vulnerability_created = models.BooleanField(default=False)
    vulnerability = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.SET_NULL, null=True, blank=True)
    
    # Raw Data
    raw_data = models.JSONField(default=dict, blank=True, help_text="Raw scanner output")
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scan', 'severity']),
            models.Index(fields=['host', 'port']),
            models.Index(fields=['processed']),
            models.Index(fields=['vulnerability_created']),
        ]
        unique_together = ['scan', 'host', 'port', 'plugin_id']

    def __str__(self):
        return f"{self.plugin_name} on {self.host}"

    @property
    def risk_score(self):
        """Calculate risk score for this finding"""
        severity_scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        base_score = severity_scores.get(self.severity, 0.0)
        
        # Adjust based on CVSS if available
        if self.cvss_base_score:
            base_score = max(base_score, self.cvss_base_score)
        
        return base_score


class ScanSchedule(models.Model):
    """Recurring scan schedules"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    
    # Schedule Configuration
    scanner = models.ForeignKey(Scanner, on_delete=models.CASCADE)
    profile = models.ForeignKey(ScanProfile, on_delete=models.CASCADE)
    
    # Targets
    target_assets = models.ManyToManyField('assets.Asset', blank=True)
    target_ranges = models.JSONField(default=list, blank=True)
    
    # Schedule Pattern
    cron_expression = models.CharField(max_length=100, help_text="Cron expression for scheduling")
    timezone = models.CharField(max_length=50, default='UTC')
    
    # Status
    is_active = models.BooleanField(default=True)
    next_run = models.DateTimeField(null=True, blank=True)
    last_run = models.DateTimeField(null=True, blank=True)
    
    # Statistics
    total_runs = models.PositiveIntegerField(default=0)
    successful_runs = models.PositiveIntegerField(default=0)
    failed_runs = models.PositiveIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.cron_expression})"
