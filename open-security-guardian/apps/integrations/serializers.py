"""Serializers for the integrations API.

Fields are listed explicitly rather than with ``'__all__'``, so that a column
added to one of these models is not served until someone decides it should
be.

None of these models holds a credential (#728). ``ExternalSystem.auth_config``
(API keys, bearer tokens, basic-auth passwords), ``WebhookEndpoint.secret_token``
and ``NotificationChannel.config`` (Slack and Teams webhook URLs, SMTP
passwords) were accepted on write, stored as plain text and never returned,
and nothing in guardian read them: it contacts no external system, receives
no webhook and delivers nothing through a channel. The columns were dropped,
and a request that sends a value for one of the three is answered 400 on
that field (``RefusedFieldsMixin``), not accepted and discarded.

``IntegrationLog`` is read-only through the API, and nothing writes an
integration log today. It had two columns for the raw request and response
of a call to an external system, ``request_data`` and ``response_data``,
which this serializer left out because such payloads carry credentials;
nothing ever filled them and they were dropped (#665).
"""

from rest_framework import serializers

from apps.core.refused_fields import RefusedFieldsMixin
from apps.core.tenancy import (
    TeamScopedModelSerializer,
    context_team_id,
    scope_to_team,
)

from .models import (
    ExternalSystem,
    IntegrationLog,
    IntegrationMapping,
    NotificationChannel,
    SyncRecord,
    WebhookEndpoint,
)


SYSTEM_CREDENTIAL_REFUSED = (
    "guardian does not store the credentials of an external system: it "
    "contacts none, so nothing would use them. Leave this field out."
)
WEBHOOK_SECRET_REFUSED = (
    "guardian does not store a webhook secret: it receives no webhooks, so "
    "nothing would verify one. Leave this field out."
)
CHANNEL_CONFIG_REFUSED = (
    "guardian does not store a channel's configuration: it delivers nothing "
    "through a channel, so nothing would use a webhook URL, a password or a "
    "token. Leave this field out."
)


class ExternalSystemSerializer(RefusedFieldsMixin, TeamScopedModelSerializer):
    is_healthy = serializers.ReadOnlyField()
    success_rate = serializers.ReadOnlyField()

    refused_fields = {"auth_config": SYSTEM_CREDENTIAL_REFUSED}

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


class WebhookEndpointSerializer(RefusedFieldsMixin, TeamScopedModelSerializer):
    refused_fields = {"secret_token": WEBHOOK_SECRET_REFUSED}

    class Meta:
        model = WebhookEndpoint
        fields = (
            "id",
            "system",
            "name",
            "endpoint_url",
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

    def validate_endpoint_url(self, value):
        """A path is taken if a webhook of the caller's own team uses it (#677).

        Only the caller's team's rows are looked at, across all of its
        external systems, so the answer says nothing about any other team:
        a path another team uses is free here, as one nobody uses is.
        """
        team_id = context_team_id(self.context)
        if team_id is None:
            # Never decide whether a path is free without knowing whose it is.
            raise serializers.ValidationError("No team to check this path for.")
        taken = scope_to_team(WebhookEndpoint.objects.all(), team_id).filter(
            endpoint_url=value
        )
        if self.instance is not None:
            taken = taken.exclude(pk=self.instance.pk)
        if taken.exists():
            raise serializers.ValidationError(
                "A webhook endpoint of your team already uses this path."
            )
        return value


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


class NotificationChannelSerializer(RefusedFieldsMixin, TeamScopedModelSerializer):
    refused_fields = {"config": CHANNEL_CONFIG_REFUSED}

    class Meta:
        model = NotificationChannel
        fields = (
            "id",
            "name",
            "channel_type",
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
