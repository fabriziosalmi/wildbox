from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from apps.assets.models import Asset
from apps.vulnerabilities.models import Vulnerability
import uuid


class ComplianceFramework(models.Model):
    """
    Compliance frameworks like NIST, PCI-DSS, GDPR, etc.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    version = models.CharField(max_length=50, blank=True)
    authority = models.CharField(max_length=100, blank=True)
    website = models.URLField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['is_active']),
        ]

    def __str__(self):
        return f"{self.name} {self.version}".strip()


class ComplianceControl(models.Model):
    """
    Individual controls within a compliance framework
    """
    CONTROL_TYPES = [
        ('preventive', 'Preventive'),
        ('detective', 'Detective'),
        ('corrective', 'Corrective'),
        ('administrative', 'Administrative'),
        ('technical', 'Technical'),
        ('physical', 'Physical'),
    ]

    CRITICALITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE, related_name='controls')
    control_id = models.CharField(max_length=50)  # e.g., "AC-2", "PCI-DSS-2.1"
    title = models.CharField(max_length=200)
    description = models.TextField()
    control_type = models.CharField(max_length=20, choices=CONTROL_TYPES)
    criticality = models.CharField(max_length=10, choices=CRITICALITY_LEVELS, default='medium')
    implementation_guidance = models.TextField(blank=True)
    testing_procedures = models.TextField(blank=True)
    related_controls = models.ManyToManyField('self', blank=True, symmetrical=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['framework', 'control_id']
        unique_together = [['framework', 'control_id']]
        indexes = [
            models.Index(fields=['framework', 'control_id']),
            models.Index(fields=['control_type']),
            models.Index(fields=['criticality']),
        ]

    def __str__(self):
        return f"{self.framework.name} - {self.control_id}: {self.title}"


class ComplianceAssessment(models.Model):
    """
    Compliance assessments and audits
    """
    ASSESSMENT_TYPES = [
        ('self_assessment', 'Self Assessment'),
        ('internal_audit', 'Internal Audit'),
        ('external_audit', 'External Audit'),
        ('penetration_test', 'Penetration Test'),
        ('vulnerability_assessment', 'Vulnerability Assessment'),
    ]

    STATUS_CHOICES = [
        ('planned', 'Planned'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE, related_name='assessments')
    assessment_type = models.CharField(max_length=30, choices=ASSESSMENT_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='planned')
    scope_description = models.TextField(blank=True)
    assets = models.ManyToManyField(Asset, blank=True, related_name='compliance_assessments')
    assessor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assessments')
    start_date = models.DateTimeField(null=True, blank=True)
    end_date = models.DateTimeField(null=True, blank=True)
    due_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['framework']),
            models.Index(fields=['status']),
            models.Index(fields=['assessment_type']),
            models.Index(fields=['due_date']),
        ]

    def __str__(self):
        return f"{self.name} - {self.framework.name}"

    @property
    def is_overdue(self):
        return self.due_date and timezone.now() > self.due_date and self.status != 'completed'


class ComplianceEvidence(models.Model):
    """
    Evidence collected for compliance controls
    """
    EVIDENCE_TYPES = [
        ('document', 'Document'),
        ('screenshot', 'Screenshot'),
        ('log_file', 'Log File'),
        ('configuration', 'Configuration'),
        ('test_result', 'Test Result'),
        ('interview', 'Interview Notes'),
        ('other', 'Other'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(ComplianceAssessment, on_delete=models.CASCADE, related_name='evidence')
    control = models.ForeignKey(ComplianceControl, on_delete=models.CASCADE, related_name='evidence')
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    evidence_type = models.CharField(max_length=20, choices=EVIDENCE_TYPES)
    file_path = models.CharField(max_length=500, blank=True)
    file_hash = models.CharField(max_length=64, blank=True)  # SHA-256
    collected_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    collected_at = models.DateTimeField(auto_now_add=True)
    is_valid = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-collected_at']
        indexes = [
            models.Index(fields=['assessment', 'control']),
            models.Index(fields=['evidence_type']),
            models.Index(fields=['collected_at']),
        ]

    def __str__(self):
        return f"{self.title} - {self.control.control_id}"


class ComplianceResult(models.Model):
    """
    Results of compliance control assessments
    """
    RESULT_STATUS = [
        ('compliant', 'Compliant'),
        ('non_compliant', 'Non-Compliant'),
        ('partially_compliant', 'Partially Compliant'),
        ('not_applicable', 'Not Applicable'),
        ('not_tested', 'Not Tested'),
    ]

    RISK_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(ComplianceAssessment, on_delete=models.CASCADE, related_name='results')
    control = models.ForeignKey(ComplianceControl, on_delete=models.CASCADE, related_name='results')
    status = models.CharField(max_length=20, choices=RESULT_STATUS)
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS, null=True, blank=True)
    findings = models.TextField(blank=True)
    recommendations = models.TextField(blank=True)
    remediation_plan = models.TextField(blank=True)
    evidence = models.ManyToManyField(ComplianceEvidence, blank=True, related_name='results')
    tested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    tested_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_results')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = [['assessment', 'control']]
        indexes = [
            models.Index(fields=['assessment', 'control']),
            models.Index(fields=['status']),
            models.Index(fields=['risk_level']),
            models.Index(fields=['tested_at']),
        ]

    def __str__(self):
        return f"{self.assessment.name} - {self.control.control_id}: {self.status}"


class ComplianceException(models.Model):
    """
    Approved exceptions to compliance requirements
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    control = models.ForeignKey(ComplianceControl, on_delete=models.CASCADE, related_name='exceptions')
    title = models.CharField(max_length=200)
    justification = models.TextField()
    compensating_controls = models.TextField(blank=True)
    risk_assessment = models.TextField(blank=True)
    assets = models.ManyToManyField(Asset, blank=True, related_name='compliance_exceptions')
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='requested_exceptions')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_exceptions')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    review_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['control']),
            models.Index(fields=['status']),
            models.Index(fields=['valid_until']),
            models.Index(fields=['review_date']),
        ]

    def __str__(self):
        return f"{self.title} - {self.control.control_id}"

    @property
    def is_expired(self):
        return timezone.now() > self.valid_until

    @property
    def needs_review(self):
        return self.review_date and timezone.now() >= self.review_date


class ComplianceMetrics(models.Model):
    """
    Compliance metrics and KPIs
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE, related_name='metrics')
    assessment = models.ForeignKey(ComplianceAssessment, on_delete=models.CASCADE, null=True, blank=True, related_name='metrics')
    metric_date = models.DateTimeField()
    total_controls = models.PositiveIntegerField()
    compliant_controls = models.PositiveIntegerField()
    non_compliant_controls = models.PositiveIntegerField()
    partially_compliant_controls = models.PositiveIntegerField()
    not_applicable_controls = models.PositiveIntegerField()
    not_tested_controls = models.PositiveIntegerField()
    compliance_percentage = models.DecimalField(max_digits=5, decimal_places=2, validators=[MinValueValidator(0), MaxValueValidator(100)])
    high_risk_findings = models.PositiveIntegerField(default=0)
    medium_risk_findings = models.PositiveIntegerField(default=0)
    low_risk_findings = models.PositiveIntegerField(default=0)
    open_exceptions = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-metric_date']
        indexes = [
            models.Index(fields=['framework', 'metric_date']),
            models.Index(fields=['assessment', 'metric_date']),
        ]

    def __str__(self):
        return f"{self.framework.name} - {self.metric_date.date()}: {self.compliance_percentage}%"
