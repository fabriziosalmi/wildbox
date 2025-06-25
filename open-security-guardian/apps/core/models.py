"""
Core Models - Base models and utilities

The Guardian: Proactive Vulnerability Management
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid


class TimestampedModel(models.Model):
    """Abstract base class with created and updated timestamps."""
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True


class UUIDModel(models.Model):
    """Abstract base class with UUID primary key."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    class Meta:
        abstract = True


class AuditableModel(TimestampedModel):
    """Abstract base class with audit fields."""
    
    created_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='%(class)s_created'
    )
    updated_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='%(class)s_updated'
    )
    
    class Meta:
        abstract = True


class BaseModel(UUIDModel, AuditableModel):
    """Base model combining UUID, timestamps, and audit fields."""
    
    class Meta:
        abstract = True


class APIKey(TimestampedModel):
    """API Key model for authentication."""
    
    name = models.CharField(max_length=255, help_text="Descriptive name for the API key")
    key = models.CharField(max_length=255, unique=True, help_text="The actual API key")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    is_active = models.BooleanField(default=True)
    last_used = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    # Permissions
    can_read = models.BooleanField(default=True)
    can_write = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)
    
    # Rate limiting
    rate_limit = models.IntegerField(default=1000, help_text="Requests per hour")
    
    class Meta:
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} - {self.key[:8]}..."
    
    def is_expired(self):
        """Check if the API key is expired."""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    def update_last_used(self):
        """Update the last used timestamp."""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])


class SystemConfiguration(TimestampedModel):
    """System-wide configuration settings."""
    
    key = models.CharField(max_length=255, unique=True)
    value = models.TextField()
    description = models.TextField(blank=True)
    is_sensitive = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "System Configuration"
        verbose_name_plural = "System Configurations"
        ordering = ['key']
    
    def __str__(self):
        return self.key
    
    @classmethod
    def get_value(cls, key, default=None):
        """Get configuration value by key."""
        try:
            config = cls.objects.get(key=key)
            return config.value
        except cls.DoesNotExist:
            return default
    
    @classmethod
    def set_value(cls, key, value, description=""):
        """Set configuration value."""
        config, created = cls.objects.get_or_create(
            key=key,
            defaults={'value': value, 'description': description}
        )
        if not created:
            config.value = value
            config.description = description
            config.save()
        return config


class AuditLog(TimestampedModel):
    """Audit log for tracking user actions."""
    
    ACTION_CHOICES = [
        ('CREATE', 'Create'),
        ('READ', 'Read'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('SCAN', 'Scan'),
        ('REMEDIATE', 'Remediate'),
        ('EXPORT', 'Export'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    api_key = models.ForeignKey(APIKey, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    resource_type = models.CharField(max_length=50)
    resource_id = models.CharField(max_length=255, blank=True)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Additional context
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['action', 'created_at']),
            models.Index(fields=['resource_type', 'resource_id']),
        ]
    
    def __str__(self):
        actor = self.user.username if self.user else 'API Key'
        return f"{actor} - {self.action} - {self.resource_type}"
