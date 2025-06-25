"""
Asset Management Models

Core models for asset discovery, inventory, and management.
"""

from django.db import models
from django.contrib.auth.models import User
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from django.utils import timezone
import uuid
import json


class AssetType(models.TextChoices):
    """Asset type choices"""
    SERVER = 'server', 'Server'
    WORKSTATION = 'workstation', 'Workstation'
    NETWORK_DEVICE = 'network_device', 'Network Device'
    MOBILE_DEVICE = 'mobile_device', 'Mobile Device'
    IOT_DEVICE = 'iot_device', 'IoT Device'
    CLOUD_INSTANCE = 'cloud_instance', 'Cloud Instance'
    CONTAINER = 'container', 'Container'
    APPLICATION = 'application', 'Application'
    DATABASE = 'database', 'Database'
    OTHER = 'other', 'Other'


class AssetCriticality(models.TextChoices):
    """Asset criticality levels"""
    CRITICAL = 'critical', 'Critical'
    HIGH = 'high', 'High'
    MEDIUM = 'medium', 'Medium'
    LOW = 'low', 'Low'
    UNKNOWN = 'unknown', 'Unknown'


class AssetStatus(models.TextChoices):
    """Asset status choices"""
    ACTIVE = 'active', 'Active'
    INACTIVE = 'inactive', 'Inactive'
    DECOMMISSIONED = 'decommissioned', 'Decommissioned'
    MAINTENANCE = 'maintenance', 'Maintenance'
    UNKNOWN = 'unknown', 'Unknown'


class Environment(models.Model):
    """Environment classification for assets"""
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    risk_weight = models.FloatField(default=1.0, help_text="Risk multiplier for this environment")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class BusinessFunction(models.Model):
    """Business function classification for assets"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    criticality_weight = models.FloatField(default=1.0, help_text="Criticality multiplier")
    compliance_required = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class Asset(models.Model):
    """Core asset model"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Basic Information
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    asset_type = models.CharField(max_length=20, choices=AssetType.choices, default=AssetType.OTHER)
    status = models.CharField(max_length=20, choices=AssetStatus.choices, default=AssetStatus.UNKNOWN)
    
    # Network Information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    fqdn = models.CharField(max_length=255, blank=True, verbose_name="FQDN")
    mac_address = models.CharField(max_length=17, blank=True)
    
    # Classification
    criticality = models.CharField(max_length=20, choices=AssetCriticality.choices, default=AssetCriticality.UNKNOWN)
    environment = models.ForeignKey(Environment, on_delete=models.SET_NULL, null=True, blank=True)
    business_function = models.ForeignKey(BusinessFunction, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Owner Information
    owner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_assets')
    technical_contact = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='managed_assets')
    
    # Metadata
    tags = models.JSONField(default=list, blank=True, help_text="List of tags for categorization")
    metadata = models.JSONField(default=dict, blank=True, help_text="Additional asset metadata")
    
    # Discovery Information
    discovered_by = models.CharField(max_length=100, blank=True, help_text="Discovery method or scanner")
    first_discovered = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    
    # Lifecycle
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_assets')

    class Meta:
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['hostname']),
            models.Index(fields=['asset_type']),
            models.Index(fields=['criticality']),
            models.Index(fields=['status']),
            models.Index(fields=['last_seen']),
        ]

    def __str__(self):
        return f"{self.name} ({self.ip_address or self.hostname})"

    @property
    def risk_score(self):
        """Calculate risk score based on criticality and environment"""
        criticality_weights = {
            AssetCriticality.CRITICAL: 5.0,
            AssetCriticality.HIGH: 4.0,
            AssetCriticality.MEDIUM: 3.0,
            AssetCriticality.LOW: 2.0,
            AssetCriticality.UNKNOWN: 1.0,
        }
        
        base_score = criticality_weights.get(self.criticality, 1.0)
        env_weight = self.environment.risk_weight if self.environment else 1.0
        func_weight = self.business_function.criticality_weight if self.business_function else 1.0
        
        return base_score * env_weight * func_weight

    @property
    def vulnerability_count(self):
        """Get count of vulnerabilities for this asset"""
        return self.vulnerabilities.filter(status='open').count()

    def add_tag(self, tag):
        """Add a tag to the asset"""
        if tag not in self.tags:
            self.tags.append(tag)
            self.save(update_fields=['tags'])

    def remove_tag(self, tag):
        """Remove a tag from the asset"""
        if tag in self.tags:
            self.tags.remove(tag)
            self.save(update_fields=['tags'])


class AssetSoftware(models.Model):
    """Software installed on assets"""
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='software')
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100, blank=True)
    vendor = models.CharField(max_length=255, blank=True)
    installation_path = models.CharField(max_length=500, blank=True)
    
    # Software metadata
    is_critical = models.BooleanField(default=False)
    is_licensed = models.BooleanField(default=True)
    license_expiry = models.DateField(null=True, blank=True)
    
    # Discovery information
    discovered_by = models.CharField(max_length=100, blank=True)
    first_discovered = models.DateTimeField(auto_now_add=True)
    last_verified = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['asset', 'name', 'version']
        ordering = ['name', 'version']

    def __str__(self):
        return f"{self.name} {self.version} on {self.asset.name}"


class AssetPort(models.Model):
    """Network ports detected on assets"""
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='ports')
    port_number = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10, choices=[('tcp', 'TCP'), ('udp', 'UDP')])
    service = models.CharField(max_length=100, blank=True)
    service_version = models.CharField(max_length=100, blank=True)
    banner = models.TextField(blank=True)
    
    # Port status
    state = models.CharField(max_length=20, choices=[
        ('open', 'Open'),
        ('closed', 'Closed'),
        ('filtered', 'Filtered'),
        ('unknown', 'Unknown')
    ], default='unknown')
    
    # Discovery information
    discovered_by = models.CharField(max_length=100, blank=True)
    first_discovered = models.DateTimeField(auto_now_add=True)
    last_verified = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['asset', 'port_number', 'protocol']
        ordering = ['port_number']

    def __str__(self):
        return f"{self.asset.name}:{self.port_number}/{self.protocol}"


class AssetGroup(models.Model):
    """Groups for organizing assets"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    assets = models.ManyToManyField(Asset, related_name='groups', blank=True)
    
    # Group properties
    auto_assignment_rules = models.JSONField(default=dict, blank=True, 
                                           help_text="Rules for automatic asset assignment")
    
    # Lifecycle
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def apply_auto_assignment_rules(self):
        """Apply automatic assignment rules to add matching assets"""
        if not self.auto_assignment_rules:
            return
        
        # Example rule structure:
        # {
        #     "asset_type": "server",
        #     "environment": "production",
        #     "tags_contain": ["web", "database"]
        # }
        
        queryset = Asset.objects.all()
        
        for field, value in self.auto_assignment_rules.items():
            if field == 'asset_type':
                queryset = queryset.filter(asset_type=value)
            elif field == 'environment':
                queryset = queryset.filter(environment__name=value)
            elif field == 'criticality':
                queryset = queryset.filter(criticality=value)
            elif field == 'tags_contain':
                for tag in value:
                    queryset = queryset.filter(tags__contains=tag)
        
        self.assets.add(*queryset)


class AssetDiscoveryRule(models.Model):
    """Rules for automatic asset discovery"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    # Discovery configuration
    discovery_type = models.CharField(max_length=50, choices=[
        ('network_scan', 'Network Scan'),
        ('cloud_api', 'Cloud API'),
        ('cmdb_import', 'CMDB Import'),
        ('agent_report', 'Agent Report'),
        ('dns_zone', 'DNS Zone Transfer')
    ])
    
    target_specification = models.JSONField(help_text="Target networks, APIs, or other discovery targets")
    schedule = models.CharField(max_length=100, help_text="Cron schedule for discovery")
    
    # Classification rules
    default_criticality = models.CharField(max_length=20, choices=AssetCriticality.choices, default=AssetCriticality.UNKNOWN)
    default_environment = models.ForeignKey(Environment, on_delete=models.SET_NULL, null=True, blank=True)
    classification_rules = models.JSONField(default=dict, blank=True)
    
    # State
    enabled = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name
