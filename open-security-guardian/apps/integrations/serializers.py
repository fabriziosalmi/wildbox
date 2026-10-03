"""Serializers for the integrations API.

Fields are listed explicitly rather than with ``'__all__'``: these models hold
credentials for external systems. ``ExternalSystem.auth_config`` carries API
keys, bearer tokens and basic-auth passwords, ``WebhookEndpoint.secret_token``
is the webhook verification secret, and ``NotificationChannel.config`` holds
channel credentials such as Slack/Teams webhook URLs or SMTP passwords. They
are accepted on write and never returned on read. ``IntegrationLog`` is
read-only through the API and leaves out ``request_data`` and
``response_data``: the raw payloads of calls to an external system can carry
the same credentials (authorization headers, OAuth token responses).
"""

from rest_framework import serializers

from apps.core.tenancy import TeamScopedModelSerializer

from .models import (
    ExternalSystem,
    IntegrationLog,
    IntegrationMapping,
    NotificationChannel,
    SyncRecord,
    WebhookEndpoint,
)


class ExternalSystemSerializer(TeamScopedModelSerializer):
    is_healthy = serializers.ReadOnlyField()
    success_rate = serializers.ReadOnlyField()

    class Meta:
        model = ExternalSystem
        fields = (
            "id",
            "name",
            "description",
            "system_type",
            "vendor",
            "version",
            "base_url",
            "api_endpoint",
            "auth_type",
            "auth_config",
            "verify_ssl",
            "timeout_seconds",
            "retry_attempts",
            "rate_limit_per_minute",
            "status",
            "last_health_check",
            "last_sync",
            "health_check_interval",
            "supports_bidirectional_sync",
            "supports_webhooks",
            "supports_real_time",
            "field_mappings",
            "sync_filters",
            "total_requests",
            "successful_requests",
            "failed_requests",
            "avg_response_time_ms",
            "tags",
            "metadata",
            "is_healthy",
            "success_rate",
            "created_at",
            "updated_at",
            "created_by",
        )
        read_only_fields = (
            "id",
            "last_health_check",
            "last_sync",
            "total_requests",
            "successful_requests",
            "failed_requests",
            "avg_response_time_ms",
            "created_at",
            "updated_at",
            "created_by",
        )
        extra_kwargs = {"auth_config": {"write_only": True}}


class IntegrationMappingSerializer(TeamScopedModelSerializer):
    class Meta:
        model = IntegrationMapping
        fields = (
            "id",
            "system",
            "guardian_entity",
            "external_entity",
            "field_mappings",
            "value_transformations",
            "sync_direction",
            "auto_sync",
            "sync_frequency",
            "sync_conditions",
            "is_active",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")


class SyncRecordSerializer(TeamScopedModelSerializer):
    class Meta:
        model = SyncRecord
        fields = (
            "id",
            "system",
            "mapping",
            "guardian_record_id",
            "external_record_id",
            "sync_status",
            "last_sync_direction",
            "created_at",
            "last_sync_at",
            "next_sync_at",
            "sync_attempts",
            "error_message",
            "conflict_details",
            "guardian_last_modified",
            "external_last_modified",
            "sync_metadata",
        )
        read_only_fields = ("id", "created_at", "last_sync_at")


class WebhookEndpointSerializer(TeamScopedModelSerializer):
    class Meta:
        model = WebhookEndpoint
        fields = (
            "id",
            "system",
            "name",
            "endpoint_url",
            "secret_token",
            "event_types",
            "filters",
            "verify_signature",
            "allowed_ips",
            "is_active",
            "last_triggered",
            "total_requests",
            "successful_requests",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "last_triggered",
            "total_requests",
            "successful_requests",
            "created_at",
            "updated_at",
        )
        extra_kwargs = {"secret_token": {"write_only": True}}


class IntegrationLogSerializer(TeamScopedModelSerializer):
    class Meta:
        model = IntegrationLog
        fields = (
            "id",
            "system",
            "operation",
            "level",
            "message",
            "details",
            "user",
            "record_id",
            "external_id",
            "response_time_ms",
            "created_at",
        )
        read_only_fields = fields


class NotificationChannelSerializer(TeamScopedModelSerializer):
    class Meta:
        model = NotificationChannel
        fields = (
            "id",
            "name",
            "channel_type",
            "config",
            "event_types",
            "severity_filter",
            "recipients",
            "is_active",
            "last_notification",
            "total_notifications",
            "created_at",
            "updated_at",
            "created_by",
        )
        read_only_fields = (
            "id",
            "last_notification",
            "total_notifications",
            "created_at",
            "updated_at",
            "created_by",
        )
        extra_kwargs = {"config": {"write_only": True}}
