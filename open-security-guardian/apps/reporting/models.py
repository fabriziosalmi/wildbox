from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid


class ReportTemplate(models.Model):
    """
    Templates for generating reports
    """
    REPORT_TYPES = [
        ('vulnerability_summary', 'Vulnerability Summary'),
        ('asset_inventory', 'Asset Inventory'),
        ('compliance_status', 'Compliance Status'),
        ('risk_assessment', 'Risk Assessment'),
        ('remediation_progress', 'Remediation Progress'),
        ('executive_dashboard', 'Executive Dashboard'),
        ('technical_details', 'Technical Details'),
        ('trend_analysis', 'Trend Analysis'),
        ('custom', 'Custom Report'),
    ]

    FORMAT_CHOICES = [
        ('pdf', 'PDF'),
        ('html', 'HTML'),
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('xlsx', 'Excel'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    report_type = models.CharField(max_length=30, choices=REPORT_TYPES)
    template_content = models.TextField()  # Template content (HTML, etc.)
    default_format = models.CharField(max_length=10, choices=FORMAT_CHOICES, default='pdf')
    filters_schema = models.JSONField(default=dict, blank=True)  # JSON schema for filters
    parameters_schema = models.JSONField(default=dict, blank=True)  # JSON schema for parameters
    is_active = models.BooleanField(default=True)
    is_public = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_templates')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['report_type']),
            models.Index(fields=['is_active']),
            models.Index(fields=['created_by']),
        ]

    def __str__(self):
        return self.name


class ReportSchedule(models.Model):
    """
    Scheduled report generation
    """
    FREQUENCY_CHOICES = [
        ('once', 'Once'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('paused', 'Paused'),
        ('disabled', 'Disabled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    template = models.ForeignKey(ReportTemplate, on_delete=models.CASCADE, related_name='schedules')
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    parameters = models.JSONField(default=dict, blank=True)  # Report parameters
    filters = models.JSONField(default=dict, blank=True)  # Report filters
    recipients = models.JSONField(default=list, blank=True)  # Email recipients
    format = models.CharField(max_length=10, choices=ReportTemplate.FORMAT_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    next_run = models.DateTimeField()
    last_run = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['next_run']
        indexes = [
            models.Index(fields=['status', 'next_run']),
            models.Index(fields=['template']),
            models.Index(fields=['created_by']),
        ]

    def __str__(self):
        return f"{self.name} - {self.frequency}"


class Report(models.Model):
    """
    Generated reports
    """
    STATUS_CHOICES = [
        ('generating', 'Generating'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    template = models.ForeignKey(ReportTemplate, on_delete=models.CASCADE, related_name='reports')
    schedule = models.ForeignKey(ReportSchedule, on_delete=models.SET_NULL, null=True, blank=True, related_name='reports')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='generating')
    format = models.CharField(max_length=10, choices=ReportTemplate.FORMAT_CHOICES)
    parameters = models.JSONField(default=dict, blank=True)
    filters = models.JSONField(default=dict, blank=True)
    file_path = models.CharField(max_length=500, blank=True)
    file_size = models.PositiveIntegerField(null=True, blank=True)  # Size in bytes
    file_hash = models.CharField(max_length=64, blank=True)  # SHA-256
    generation_time = models.DurationField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['template']),
            models.Index(fields=['status']),
            models.Index(fields=['generated_at']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"{self.name} - {self.generated_at.date()}"

    @property
    def is_expired(self):
        return self.expires_at and timezone.now() > self.expires_at


class Dashboard(models.Model):
    """
    Custom dashboards
    """
    DASHBOARD_TYPES = [
        ('executive', 'Executive'),
        ('security', 'Security'),
        ('compliance', 'Compliance'),
        ('operational', 'Operational'),
        ('custom', 'Custom'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    dashboard_type = models.CharField(max_length=20, choices=DASHBOARD_TYPES)
    layout_config = models.JSONField(default=dict)  # Dashboard layout configuration
    widgets_config = models.JSONField(default=list)  # Widget configurations
    filters_config = models.JSONField(default=dict, blank=True)  # Default filters
    refresh_interval = models.PositiveIntegerField(default=300)  # Seconds
    is_active = models.BooleanField(default=True)
    is_public = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_dashboards')
    shared_with = models.ManyToManyField(User, blank=True, related_name='shared_dashboards')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['dashboard_type']),
            models.Index(fields=['is_active']),
            models.Index(fields=['created_by']),
        ]

    def __str__(self):
        return self.name


class Widget(models.Model):
    """
    Dashboard widgets
    """
    WIDGET_TYPES = [
        ('chart', 'Chart'),
        ('table', 'Table'),
        ('metric', 'Metric'),
        ('gauge', 'Gauge'),
        ('progress', 'Progress Bar'),
        ('list', 'List'),
        ('map', 'Map'),
        ('custom', 'Custom'),
    ]

    CHART_TYPES = [
        ('line', 'Line Chart'),
        ('bar', 'Bar Chart'),
        ('pie', 'Pie Chart'),
        ('donut', 'Donut Chart'),
        ('area', 'Area Chart'),
        ('scatter', 'Scatter Plot'),
        ('heatmap', 'Heatmap'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    widget_type = models.CharField(max_length=20, choices=WIDGET_TYPES)
    chart_type = models.CharField(max_length=20, choices=CHART_TYPES, blank=True, null=True)
    data_source = models.CharField(max_length=100)  # API endpoint or data source
    query_config = models.JSONField(default=dict)  # Query configuration
    display_config = models.JSONField(default=dict)  # Display configuration
    refresh_interval = models.PositiveIntegerField(default=300)  # Seconds
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['widget_type']),
            models.Index(fields=['is_active']),
            models.Index(fields=['data_source']),
        ]

    def __str__(self):
        return self.name


class ReportMetrics(models.Model):
    """
    Metrics for report usage and performance
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    template = models.ForeignKey(ReportTemplate, on_delete=models.CASCADE, related_name='metrics')
    metric_date = models.DateTimeField()
    generation_count = models.PositiveIntegerField(default=0)
    avg_generation_time = models.DurationField(null=True, blank=True)
    success_rate = models.DecimalField(max_digits=5, decimal_places=2, validators=[MinValueValidator(0), MaxValueValidator(100)])
    total_file_size = models.PositiveBigIntegerField(default=0)  # Total size in bytes
    unique_users = models.PositiveIntegerField(default=0)
    download_count = models.PositiveIntegerField(default=0)
    error_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-metric_date']
        unique_together = [['template', 'metric_date']]
        indexes = [
            models.Index(fields=['template', 'metric_date']),
            models.Index(fields=['metric_date']),
        ]

    def __str__(self):
        return f"{self.template.name} - {self.metric_date.date()}"


class AlertRule(models.Model):
    """
    Alert rules for automated notifications based on report data
    """
    CONDITION_TYPES = [
        ('threshold', 'Threshold'),
        ('change', 'Change'),
        ('trend', 'Trend'),
        ('anomaly', 'Anomaly'),
    ]

    OPERATORS = [
        ('gt', 'Greater Than'),
        ('lt', 'Less Than'),
        ('eq', 'Equal To'),
        ('gte', 'Greater Than or Equal'),
        ('lte', 'Less Than or Equal'),
        ('ne', 'Not Equal'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    data_source = models.CharField(max_length=100)  # API endpoint or data source
    condition_type = models.CharField(max_length=20, choices=CONDITION_TYPES)
    condition_config = models.JSONField(default=dict)  # Condition configuration
    threshold_value = models.FloatField(null=True, blank=True)
    operator = models.CharField(max_length=10, choices=OPERATORS, blank=True)
    notification_config = models.JSONField(default=dict)  # Notification settings
    is_active = models.BooleanField(default=True)
    last_triggered = models.DateTimeField(null=True, blank=True)
    trigger_count = models.PositiveIntegerField(default=0)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['is_active']),
            models.Index(fields=['condition_type']),
            models.Index(fields=['last_triggered']),
        ]

    def __str__(self):
        return self.name
