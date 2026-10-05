"""
External System Integration Views

Django REST Framework views for the records of external systems.

guardian stores these records and does nothing with them: no code contacts
an external system, runs a synchronization, receives or sends a webhook, or
delivers through a notification channel. The actions that claimed to
(``test_connection``, ``health_check``, ``sync_status``, ``test_mapping``,
``sync_now``, ``sync_statistics``, ``retry_sync``, ``test_webhook``,
``trigger_webhook``, ``error_summary``, ``test_notification`` and
``send_notification``) answered a fixed success, or fixed figures, without
doing anything, and were removed (#644). An action added here must do what
its response says: tests/unit/test_action_contracts.py fails for one that
answers success and changes nothing.
"""

from datetime import timedelta

from django.utils import timezone
from rest_framework import viewsets, status
from apps.core.permissions import IsGatewayAdminOrReadOnly
from apps.core.tenancy import TeamScopedViewSetMixin
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from .models import (
    ExternalSystem, IntegrationMapping, SyncRecord,
    WebhookEndpoint, IntegrationLog, NotificationChannel
)
from .serializers import (
    ExternalSystemSerializer, IntegrationLogSerializer,
    IntegrationMappingSerializer, NotificationChannelSerializer,
    SyncRecordSerializer, WebhookEndpointSerializer,
)


class ExternalSystemViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing external system integrations"""
    queryset = ExternalSystem.objects.all()
    serializer_class = ExternalSystemSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description', 'vendor']
    filterset_fields = ['system_type', 'status', 'auth_type']
    ordering_fields = ['name', 'created_at', 'last_health_check']
    ordering = ['name']

    def perform_create(self, serializer):
        """Record the gateway-authenticated user as the creator."""
        serializer.save(created_by=self.request.user)


class IntegrationMappingViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing field mappings between Guardian and external systems"""
    queryset = IntegrationMapping.objects.all()
    serializer_class = IntegrationMappingSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['system', 'guardian_entity', 'sync_direction', 'is_active']
    ordering_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']


class SyncRecordViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing synchronization records"""
    queryset = SyncRecord.objects.all()
    serializer_class = SyncRecordSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['system', 'mapping', 'sync_status', 'last_sync_direction']
    ordering_fields = ['last_sync_at', 'next_sync_at', 'created_at']
    ordering = ['-last_sync_at']


class WebhookEndpointViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing webhook endpoints"""
    queryset = WebhookEndpoint.objects.all()
    serializer_class = WebhookEndpointSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'endpoint_url']
    # event_types is a JSON list; django-filter cannot build an exact filter
    # for a JSONField, so it is not filterable here.
    filterset_fields = ['system', 'is_active']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']


#: ``cleanup_logs`` deletes the logs older than this many days when the
#: request does not say (the default the route always documented).
DEFAULT_LOG_RETENTION_DAYS = 30


class IntegrationLogViewSet(TeamScopedViewSetMixin, viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing integration logs"""
    queryset = IntegrationLog.objects.all()
    serializer_class = IntegrationLogSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['system', 'operation', 'level', 'record_id']
    search_fields = ['message', 'external_id']
    ordering_fields = ['created_at', 'level']
    ordering = ['-created_at']

    @action(detail=False, methods=['delete'])
    def cleanup_logs(self, request):
        """Delete the team's integration logs older than ``older_than_days``.

        This answered "Logs older than N days cleaned up" and deleted
        nothing (#644). It deletes the caller's team's logs only
        (``get_queryset``), needs the owner or admin role like every other
        write, and reports how many rows went.
        """
        raw = request.query_params.get('older_than_days', DEFAULT_LOG_RETENTION_DAYS)
        try:
            days = int(raw)
        except (TypeError, ValueError):
            days = 0
        # Bounded above so the cutoff stays a date timedelta can compute.
        if not 1 <= days <= 36500:
            return Response(
                {'older_than_days': ['A whole number of days, 1 or more.']},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cutoff = timezone.now() - timedelta(days=days)
        _, per_model = self.get_queryset().filter(created_at__lt=cutoff).delete()
        return Response({
            'deleted': per_model.get(IntegrationLog._meta.label, 0),
            'older_than_days': days,
        })


class NotificationChannelViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing notification channels"""
    queryset = NotificationChannel.objects.all()
    serializer_class = NotificationChannelSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name']
    # severity_filter is a JSON list; django-filter cannot build an exact
    # filter for a JSONField, so it is not filterable here.
    filterset_fields = ['channel_type', 'is_active']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']

    def perform_create(self, serializer):
        """Record the gateway-authenticated user as the creator."""
        serializer.save(created_by=self.request.user)
