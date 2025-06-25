"""
Vulnerability Management Models

Core models for vulnerability tracking, risk assessment, and lifecycle management.
"""

from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
import uuid
import json


class VulnerabilitySeverity(models.TextChoices):
    """Vulnerability severity levels"""
    CRITICAL = 'critical', 'Critical'
    HIGH = 'high', 'High'
    MEDIUM = 'medium', 'Medium'
    LOW = 'low', 'Low'
    INFO = 'info', 'Info'


class VulnerabilityStatus(models.TextChoices):
    """Vulnerability status choices"""
    OPEN = 'open', 'Open'
    IN_PROGRESS = 'in_progress', 'In Progress'
    RESOLVED = 'resolved', 'Resolved'
    ACCEPTED = 'accepted', 'Accepted'
    FALSE_POSITIVE = 'false_positive', 'False Positive'
    DUPLICATE = 'duplicate', 'Duplicate'


class ThreatLevel(models.TextChoices):
    """Threat level based on intelligence"""
    IMMINENT = 'imminent', 'Imminent'
    ACTIVE = 'active', 'Active'
    EMERGING = 'emerging', 'Emerging'
    POSSIBLE = 'possible', 'Possible'
    UNKNOWN = 'unknown', 'Unknown'


class Vulnerability(models.Model):
    """Core vulnerability model"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Basic Information
    title = models.CharField(max_length=500)
    description = models.TextField()
    cve_id = models.CharField(max_length=20, blank=True, db_index=True)
    
    # Affected Asset
    asset = models.ForeignKey('assets.Asset', on_delete=models.CASCADE, related_name='vulnerabilities')
    
    # Vulnerability Details
    severity = models.CharField(max_length=20, choices=VulnerabilitySeverity.choices, default=VulnerabilitySeverity.MEDIUM)
    cvss_v3_score = models.FloatField(null=True, blank=True, validators=[MinValueValidator(0.0), MaxValueValidator(10.0)])
    cvss_v3_vector = models.CharField(max_length=200, blank=True)
    
    # Risk Assessment
    risk_score = models.FloatField(default=0.0, validators=[MinValueValidator(0.0), MaxValueValidator(10.0)])
    threat_level = models.CharField(max_length=20, choices=ThreatLevel.choices, default=ThreatLevel.UNKNOWN)
    exploitability_score = models.FloatField(default=0.0, validators=[MinValueValidator(0.0), MaxValueValidator(10.0)])
    business_impact_score = models.FloatField(default=0.0, validators=[MinValueValidator(0.0), MaxValueValidator(10.0)])
    
    # Status and Lifecycle
    status = models.CharField(max_length=20, choices=VulnerabilityStatus.choices, default=VulnerabilityStatus.OPEN)
    priority = models.CharField(max_length=20, choices=[
        ('p1', 'P1 - Emergency'),
        ('p2', 'P2 - High'),
        ('p3', 'P3 - Medium'),
        ('p4', 'P4 - Low')
    ], default='p3')
    
    # Technical Details
    port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, blank=True)
    service = models.CharField(max_length=100, blank=True)
    plugin_id = models.CharField(max_length=100, blank=True, help_text="Scanner plugin ID")
    
    # Evidence and Proof
    evidence = models.TextField(blank=True, help_text="Evidence or proof of concept")
    solution = models.TextField(blank=True, help_text="Recommended solution")
    references = models.JSONField(default=list, blank=True, help_text="List of reference URLs")
    
    # Source Information
    scanner = models.CharField(max_length=100, blank=True, help_text="Scanner that found this vulnerability")
    scan_id = models.CharField(max_length=100, blank=True, help_text="Scan ID for tracking")
    
    # Assignment
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_vulnerabilities')
    assignee_group = models.CharField(max_length=100, blank=True, help_text="Team or group assigned")
    
    # SLA and Due Dates
    due_date = models.DateTimeField(null=True, blank=True)
    sla_hours = models.PositiveIntegerField(null=True, blank=True, help_text="SLA in hours based on priority")
    
    # Lifecycle Timestamps
    first_discovered = models.DateTimeField(auto_now_add=True)
    last_detected = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    tags = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True, help_text="Additional vulnerability metadata")
    
    # Created/Updated
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_vulnerabilities')

    class Meta:
        ordering = ['-risk_score', '-cvss_v3_score', '-created_at']
        indexes = [
            models.Index(fields=['cve_id']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['priority']),
            models.Index(fields=['risk_score']),
            models.Index(fields=['due_date']),
            models.Index(fields=['asset', 'status']),
        ]
        unique_together = ['asset', 'cve_id', 'port']  # Prevent duplicate findings

    def __str__(self):
        return f"{self.cve_id or self.title} on {self.asset.name}"

    def save(self, *args, **kwargs):
        """Override save to calculate risk score and set due date"""
        self.risk_score = self.calculate_risk_score()
        
        if not self.due_date and self.status == VulnerabilityStatus.OPEN:
            self.due_date = self.calculate_due_date()
            
        super().save(*args, **kwargs)

    def calculate_risk_score(self):
        """Calculate contextual risk score"""
        # Base score from CVSS
        base_score = self.cvss_v3_score or 0.0
        
        # Asset criticality multiplier
        asset_risk = self.asset.risk_score if hasattr(self.asset, 'risk_score') else 1.0
        
        # Threat level multiplier
        threat_multipliers = {
            ThreatLevel.IMMINENT: 2.0,
            ThreatLevel.ACTIVE: 1.8,
            ThreatLevel.EMERGING: 1.5,
            ThreatLevel.POSSIBLE: 1.2,
            ThreatLevel.UNKNOWN: 1.0,
        }
        threat_multiplier = threat_multipliers.get(self.threat_level, 1.0)
        
        # Exploitability factor
        exploit_factor = (self.exploitability_score / 10.0) if self.exploitability_score else 0.1
        
        # Business impact factor
        business_factor = (self.business_impact_score / 10.0) if self.business_impact_score else 0.5
        
        # Calculate final risk score
        risk_score = (base_score * asset_risk * threat_multiplier * exploit_factor * business_factor) / 10.0
        
        return min(10.0, max(0.0, risk_score))

    def calculate_due_date(self):
        """Calculate due date based on priority and SLA"""
        if not self.sla_hours:
            # Default SLA hours based on priority
            sla_map = {
                'p1': 4,    # 4 hours for emergency
                'p2': 24,   # 1 day for high
                'p3': 168,  # 1 week for medium
                'p4': 720,  # 30 days for low
            }
            self.sla_hours = sla_map.get(self.priority, 168)
        
        return timezone.now() + timezone.timedelta(hours=self.sla_hours)

    @property
    def is_overdue(self):
        """Check if vulnerability is overdue"""
        return self.due_date and timezone.now() > self.due_date and self.status == VulnerabilityStatus.OPEN

    @property
    def days_to_due(self):
        """Calculate days until due date"""
        if not self.due_date:
            return None
        delta = self.due_date - timezone.now()
        return delta.days

    def add_tag(self, tag):
        """Add a tag to the vulnerability"""
        if tag not in self.tags:
            self.tags.append(tag)
            self.save(update_fields=['tags'])

    def remove_tag(self, tag):
        """Remove a tag from the vulnerability"""
        if tag in self.tags:
            self.tags.remove(tag)
            self.save(update_fields=['tags'])


class VulnerabilityTemplate(models.Model):
    """Template for common vulnerabilities with standard descriptions and solutions"""
    cve_id = models.CharField(max_length=20, unique=True, blank=True)
    title = models.CharField(max_length=500)
    description_template = models.TextField()
    solution_template = models.TextField()
    severity = models.CharField(max_length=20, choices=VulnerabilitySeverity.choices)
    cvss_v3_score = models.FloatField(null=True, blank=True)
    cvss_v3_vector = models.CharField(max_length=200, blank=True)
    
    # Classification
    category = models.CharField(max_length=100, blank=True)
    cwe_id = models.CharField(max_length=20, blank=True, help_text="Common Weakness Enumeration ID")
    owasp_category = models.CharField(max_length=100, blank=True)
    
    # Default SLA and priority
    default_priority = models.CharField(max_length=10, choices=[
        ('p1', 'P1 - Emergency'),
        ('p2', 'P2 - High'),
        ('p3', 'P3 - Medium'),
        ('p4', 'P4 - Low')
    ], default='p3')
    default_sla_hours = models.PositiveIntegerField(default=168)
    
    # References and metadata
    references = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['cve_id', 'title']

    def __str__(self):
        return f"{self.cve_id} - {self.title}" if self.cve_id else self.title


class VulnerabilityAssessment(models.Model):
    """Risk assessment details for vulnerabilities"""
    vulnerability = models.OneToOneField(Vulnerability, on_delete=models.CASCADE, related_name='assessment')
    
    # Threat Intelligence Data
    exploit_available = models.BooleanField(default=False)
    exploit_public = models.BooleanField(default=False)
    exploit_weaponized = models.BooleanField(default=False)
    active_campaigns = models.BooleanField(default=False)
    threat_actor_interest = models.CharField(max_length=20, choices=[
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('unknown', 'Unknown')
    ], default='unknown')
    
    # Environmental Factors
    network_exposure = models.CharField(max_length=20, choices=[
        ('internet', 'Internet Facing'),
        ('internal', 'Internal Network'),
        ('isolated', 'Isolated/DMZ'),
        ('unknown', 'Unknown')
    ], default='unknown')
    
    data_sensitivity = models.CharField(max_length=20, choices=[
        ('public', 'Public'),
        ('internal', 'Internal'),
        ('confidential', 'Confidential'),
        ('restricted', 'Restricted')
    ], default='internal')
    
    # Compensating Controls
    waf_protection = models.BooleanField(default=False)
    network_segmentation = models.BooleanField(default=False)
    monitoring_coverage = models.BooleanField(default=False)
    access_restrictions = models.BooleanField(default=False)
    
    # Business Impact Assessment
    availability_impact = models.CharField(max_length=20, choices=[
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('none', 'None')
    ], default='medium')
    
    confidentiality_impact = models.CharField(max_length=20, choices=[
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('none', 'None')
    ], default='medium')
    
    integrity_impact = models.CharField(max_length=20, choices=[
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('none', 'None')
    ], default='medium')
    
    # Assessment Details
    assessed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    assessed_at = models.DateTimeField(auto_now=True)
    assessment_notes = models.TextField(blank=True)
    
    # Calculated Scores
    threat_intelligence_score = models.FloatField(default=0.0)
    environmental_score = models.FloatField(default=0.0)
    business_impact_score = models.FloatField(default=0.0)

    def save(self, *args, **kwargs):
        """Calculate assessment scores"""
        self.threat_intelligence_score = self.calculate_threat_score()
        self.environmental_score = self.calculate_environmental_score()
        self.business_impact_score = self.calculate_business_impact_score()
        
        super().save(*args, **kwargs)
        
        # Update parent vulnerability
        self.vulnerability.exploitability_score = self.threat_intelligence_score
        self.vulnerability.business_impact_score = self.business_impact_score
        self.vulnerability.save()

    def calculate_threat_score(self):
        """Calculate threat intelligence score"""
        score = 0.0
        
        if self.exploit_available:
            score += 3.0
        if self.exploit_public:
            score += 2.0
        if self.exploit_weaponized:
            score += 3.0
        if self.active_campaigns:
            score += 2.0
        
        # Threat actor interest multiplier
        interest_multipliers = {
            'high': 1.5,
            'medium': 1.2,
            'low': 1.0,
            'unknown': 1.0
        }
        score *= interest_multipliers.get(self.threat_actor_interest, 1.0)
        
        return min(10.0, score)

    def calculate_environmental_score(self):
        """Calculate environmental exposure score"""
        score = 5.0  # Base score
        
        # Network exposure factor
        exposure_factors = {
            'internet': 2.0,
            'internal': 1.0,
            'isolated': 0.5,
            'unknown': 1.0
        }
        score *= exposure_factors.get(self.network_exposure, 1.0)
        
        # Data sensitivity factor
        sensitivity_factors = {
            'public': 0.5,
            'internal': 1.0,
            'confidential': 1.5,
            'restricted': 2.0
        }
        score *= sensitivity_factors.get(self.data_sensitivity, 1.0)
        
        # Compensating controls reduction
        controls_count = sum([
            self.waf_protection,
            self.network_segmentation,
            self.monitoring_coverage,
            self.access_restrictions
        ])
        score *= (1.0 - (controls_count * 0.1))  # 10% reduction per control
        
        return min(10.0, max(0.0, score))

    def calculate_business_impact_score(self):
        """Calculate business impact score"""
        impact_weights = {
            'high': 3.0,
            'medium': 2.0,
            'low': 1.0,
            'none': 0.0
        }
        
        availability_score = impact_weights.get(self.availability_impact, 2.0)
        confidentiality_score = impact_weights.get(self.confidentiality_impact, 2.0)
        integrity_score = impact_weights.get(self.integrity_impact, 2.0)
        
        # Weighted average (availability is often most critical)
        score = (availability_score * 0.4 + confidentiality_score * 0.3 + integrity_score * 0.3)
        
        # Normalize to 0-10 scale
        return (score / 3.0) * 10.0


class VulnerabilityNote(models.Model):
    """Notes and comments on vulnerabilities"""
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    note_type = models.CharField(max_length=20, choices=[
        ('general', 'General'),
        ('analysis', 'Analysis'),
        ('remediation', 'Remediation'),
        ('escalation', 'Escalation'),
        ('approval', 'Approval')
    ], default='general')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Note on {self.vulnerability.title} by {self.author.username}"


class VulnerabilityHistory(models.Model):
    """History of vulnerability status changes"""
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='history')
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    # Change details
    field_name = models.CharField(max_length=50)
    old_value = models.TextField(blank=True)
    new_value = models.TextField(blank=True)
    change_reason = models.TextField(blank=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.vulnerability.title}: {self.field_name} changed"
