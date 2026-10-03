"""
Core Models - Base models and utilities

The Guardian: Proactive Vulnerability Management
"""

from django.db import models
from django.contrib.auth.models import User
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


# guardian had its own APIKey model here, stored in plain text and accepted
# beside the gateway as an admin and a superuser (#629). It was removed with
# migration 0002_remove_apikey: callers authenticate through the gateway with
# identity's personal API keys.


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
        actor = self.user.username if self.user else 'unknown'
        return f"{actor} - {self.action} - {self.resource_type}"


def team_id_field():
    """The team a tenant-owned row belongs to (#642).

    Nullable: rows written before guardian kept a team have none, and no
    team reaches them until an operator assigns them
    (``manage.py assign_guardian_team``). Not editable: the API sets it from
    the gateway's X-Wildbox-Team-ID, never from a request body.
    """
    return models.UUIDField(null=True, blank=True, editable=False, db_index=True)


class TeamMembership(models.Model):
    """A gateway user seen acting as a member of a team (#642).

    auth.User rows mirror the identity service's users and carry no team:
    a user may belong to several. GatewayAuthMiddleware records each
    (team, user) pair it authenticates, and a team can reference -- assign
    a vulnerability to, share a dashboard with -- only the users recorded
    for it. Without this, any integer user id was accepted, and the
    response named that user to a team they are not in.
    """

    team_id = models.UUIDField(db_index=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='guardian_team_memberships'
    )
    first_seen = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('team_id', 'user')]

    def __str__(self):
        return f"{self.user.username} in {self.team_id}"


class TeamTask(models.Model):
    """The team that dispatched a Celery task, for its status route (#642).

    /api/v1/tasks/<task_id>/ reads the state of a task from the result
    backend, which knows nothing of teams. An endpoint that answers with a
    task_id records it here, and the status route answers 404 to any other
    team, as it does for an id nobody dispatched.
    """

    task_id = models.CharField(max_length=255, unique=True)
    team_id = models.UUIDField(null=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.task_id} ({self.team_id})"
