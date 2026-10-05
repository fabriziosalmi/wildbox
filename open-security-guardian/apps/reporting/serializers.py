from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from rest_framework import serializers

from apps.core.tenancy import (
    TeamScopedModelSerializer,
    context_team_id,
    scope_to_team,
)
from .alert_metrics import UnsupportedAlertRule, parse_rule
from .models import (
    ReportTemplate, ReportSchedule, Report, Dashboard, Widget,
    ReportMetrics, AlertRule, AlertNotification,
    SUPPORTED_REPORT_FORMATS, SUPPORTED_REPORT_TYPES,
)


def validate_email_list(value, not_a_list_message):
    """A list of e-mail addresses, shared by report schedules (#548) and alert rules (#549)."""
    if not isinstance(value, list):
        raise serializers.ValidationError(not_a_list_message)
    for address in value:
        try:
            validate_email(address)
        except (DjangoValidationError, TypeError):
            raise serializers.ValidationError(f"{address!r} is not an e-mail address.")
    return value


class ReportTemplateSerializer(TeamScopedModelSerializer):
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    reports_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ReportTemplate
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_reports_count(self, obj):
        return obj.reports.count()


class ReportScheduleSerializer(TeamScopedModelSerializer):
    template_name = serializers.CharField(source='template.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        model = ReportSchedule
        fields = '__all__'
        # last_run is when the dispatcher last ran it (#548).
        read_only_fields = ('id', 'created_at', 'updated_at', 'last_run')

    def validate_recipients(self, value):
        """A list of e-mail addresses: they are sent each report (#548)."""
        return validate_email_list(value, "Recipients must be a list of e-mail addresses.")

    def validate(self, attrs):
        """Refuse a schedule that would only ever produce failed or empty reports (#548)."""
        attrs = super().validate(attrs)
        template = attrs.get('template', getattr(self.instance, 'template', None))
        report_format = attrs.get('format', getattr(self.instance, 'format', None))
        errors = {}
        if template is not None and template.report_type not in SUPPORTED_REPORT_TYPES:
            errors['template'] = (
                f"{template.get_report_type_display()} reports cannot be scheduled: "
                "they have no data behind them. Schedulable report types: "
                f"{', '.join(SUPPORTED_REPORT_TYPES)}."
            )
        if report_format is not None and report_format not in SUPPORTED_REPORT_FORMATS:
            errors['format'] = (
                f"{report_format} reports are not generated yet. "
                f"Schedulable formats: {', '.join(SUPPORTED_REPORT_FORMATS)}."
            )
        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class ReportSerializer(TeamScopedModelSerializer):
    template_name = serializers.CharField(source='template.name', read_only=True)
    schedule_name = serializers.CharField(source='schedule.name', read_only=True)
    generated_by_name = serializers.CharField(source='generated_by.get_full_name', read_only=True)
    is_expired = serializers.ReadOnlyField()
    file_size_mb = serializers.SerializerMethodField()
    
    class Meta:
        model = Report
        fields = '__all__'
        # Where the file is, and what generating it recorded, is guardian's
        # to write: a file_path from a request would let the download serve
        # any file the process can read (#642).
        read_only_fields = (
            'id', 'generated_at', 'generated_by', 'file_path', 'file_size',
            'file_hash', 'generation_time', 'error_message', 'expires_at',
        )
    
    def get_file_size_mb(self, obj):
        if obj.file_size:
            return round(obj.file_size / (1024 * 1024), 2)
        return None


class DashboardSerializer(TeamScopedModelSerializer):
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    shared_with_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Dashboard
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_shared_with_count(self, obj):
        return obj.shared_with.count()


class WidgetSerializer(TeamScopedModelSerializer):
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        model = Widget
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


class ReportMetricsSerializer(TeamScopedModelSerializer):
    template_name = serializers.CharField(source='template.name', read_only=True)
    avg_generation_time_seconds = serializers.SerializerMethodField()
    
    class Meta:
        model = ReportMetrics
        fields = '__all__'
        read_only_fields = ('id', 'created_at')
    
    def get_avg_generation_time_seconds(self, obj):
        if obj.avg_generation_time:
            return obj.avg_generation_time.total_seconds()
        return None


class AlertRuleSerializer(TeamScopedModelSerializer):
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)

    class Meta:
        model = AlertRule
        fields = '__all__'
        # The evaluation state is guardian's to keep (#549).
        read_only_fields = (
            'id', 'created_at', 'updated_at', 'last_triggered', 'trigger_count',
            'state', 'firing_since', 'last_value', 'last_evaluated_at',
            'last_notified_at',
        )

    def validate_notification_config(self, value):
        """An object; its 'recipients', if any, a list of e-mail addresses."""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Must be an object.")
        validate_email_list(
            value.get('recipients', []),
            "'recipients' must be a list of e-mail addresses.",
        )
        return value

    def validate(self, attrs):
        """Refuse a rule guardian cannot evaluate (#549).

        Every rule used to be evaluated against 0, so a rule naming anything
        at all was accepted. The metric, the condition and its filters must
        now be ones alert_metrics.py computes.
        """
        attrs = super().validate(attrs)

        def current(name, default=None):
            if name in attrs:
                return attrs[name]
            return getattr(self.instance, name, default)

        try:
            _, filters = parse_rule(
                current('data_source'),
                current('condition_type'),
                current('operator'),
                current('threshold_value'),
                current('condition_config', {}),
            )
        except UnsupportedAlertRule as exc:
            raise serializers.ValidationError(exc.args[0])
        if 'asset' in filters:
            # The rule's metric is its team's (#642); an asset of another
            # team is refused like one that does not exist.
            from apps.assets.models import Asset

            assets = scope_to_team(
                Asset.objects.filter(pk=filters['asset']),
                context_team_id(self.context),
            )
            if not assets.exists():
                raise serializers.ValidationError(
                    {'condition_config': f"asset {filters['asset']} does not exist"}
                )
        return attrs


class AlertNotificationSerializer(TeamScopedModelSerializer):
    class Meta:
        model = AlertNotification
        fields = (
            'id', 'kind', 'value', 'threshold_value', 'operator', 'recipients',
            'delivered', 'failure_reason', 'created_at',
        )
        read_only_fields = fields
