"""Serializers for the remediation API.

Fields are listed explicitly so that a field added to a model later is not
exposed by default.
"""

from rest_framework import serializers

from apps.core.tenancy import TeamScopedModelSerializer

from .models import (
    RemediationComment,
    RemediationStep,
    RemediationTemplate,
    RemediationTicket,
    RemediationWorkflow,
)


class RemediationTicketSerializer(TeamScopedModelSerializer):
    is_overdue = serializers.ReadOnlyField()
    days_until_due = serializers.ReadOnlyField()

    class Meta:
        model = RemediationTicket
        fields = (
            "id",
            "title",
            "description",
            "system",
            "external_ticket_id",
            "external_url",
            "priority",
            "status",
            "assigned_to",
            "assigned_team",
            "created_at",
            "updated_at",
            "due_date",
            "completed_at",
            "system_metadata",
            "sync_enabled",
            "last_sync",
            "is_overdue",
            "days_until_due",
            "created_by",
        )
        read_only_fields = ("id", "created_at", "updated_at", "last_sync", "created_by")


class RemediationWorkflowSerializer(TeamScopedModelSerializer):
    is_overdue = serializers.ReadOnlyField()
    duration_days = serializers.ReadOnlyField()

    class Meta:
        model = RemediationWorkflow
        fields = (
            "id",
            "vulnerability",
            "title",
            "description",
            "remediation_type",
            "status",
            "priority",
            "assigned_to",
            "assigned_team",
            "approver",
            "ticket",
            "estimated_effort_hours",
            "actual_effort_hours",
            "planned_start_date",
            "actual_start_date",
            "planned_completion_date",
            "actual_completion_date",
            "remediation_steps",
            "rollback_plan",
            "testing_plan",
            "business_justification",
            "maintenance_window_required",
            "downtime_expected_minutes",
            "affected_systems",
            "blocking_issues",
            "prerequisite_tasks",
            "progress_percentage",
            "current_step",
            "implementation_risk",
            "risk_mitigation_notes",
            "tags",
            "metadata",
            "is_overdue",
            "duration_days",
            "created_at",
            "updated_at",
            "created_by",
        )
        read_only_fields = ("id", "created_at", "updated_at", "created_by")


class RemediationStepSerializer(TeamScopedModelSerializer):
    class Meta:
        model = RemediationStep
        fields = (
            "id",
            "workflow",
            "title",
            "description",
            "order",
            "status",
            "assigned_to",
            "estimated_duration_minutes",
            "actual_duration_minutes",
            "started_at",
            "completed_at",
            "instructions",
            "validation_criteria",
            "automation_script",
            "execution_notes",
            "validation_results",
            "attachments",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")


class RemediationCommentSerializer(TeamScopedModelSerializer):
    class Meta:
        model = RemediationComment
        fields = (
            "id",
            "workflow",
            "author",
            "content",
            "comment_type",
            "is_internal",
            "attachments",
            "created_at",
            "updated_at",
        )
        # The viewset sets the author from the request in perform_create.
        read_only_fields = ("id", "author", "created_at", "updated_at")


class RemediationTemplateSerializer(TeamScopedModelSerializer):
    class Meta:
        model = RemediationTemplate
        fields = (
            "id",
            "name",
            "description",
            "category",
            "remediation_type",
            "default_priority",
            "estimated_effort_hours",
            "step_templates",
            "rollback_template",
            "testing_template",
            "usage_count",
            "success_rate",
            "vulnerability_types",
            "asset_types",
            "is_active",
            "created_at",
            "updated_at",
            "created_by",
        )
        read_only_fields = (
            "id",
            "usage_count",
            "success_rate",
            "created_at",
            "updated_at",
            "created_by",
        )
