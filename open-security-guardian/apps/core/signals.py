"""
Core Signals - Django signal handlers

The Guardian: Proactive Vulnerability Management
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from apps.core.models import AuditLog
from apps.core.logging import SecurityLogger

security_logger = SecurityLogger('signals')


@receiver(post_save, sender=User)
def user_created_or_updated(sender, instance, created, **kwargs):
    """Handle user creation or update."""
    if created:
        security_logger.logger.info(
            f"New user created: {instance.username}",
            extra={
                'event_type': 'user_management',
                'action': 'user_created',
                'username': instance.username,
                'email': instance.email,
            }
        )


@receiver(post_delete, sender=User)
def user_deleted(sender, instance, **kwargs):
    """Handle user deletion."""
    security_logger.logger.warning(
        f"User deleted: {instance.username}",
        extra={
            'event_type': 'user_management',
            'action': 'user_deleted',
            'username': instance.username,
            'email': instance.email,
        }
    )
