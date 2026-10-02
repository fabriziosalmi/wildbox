from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from rest_framework import serializers
from .alert_metrics import UnsupportedAlertRule, parse_rule
from .models import (
    ReportTemplate, ReportSchedule, Report, Dashboard, Widget,
    ReportMetrics, AlertRule, AlertNotification
)


class ReportTemplateSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    reports_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ReportTemplate
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_reports_count(self, obj):
        return obj.reports.count()


class ReportScheduleSerializer(serializers.ModelSerializer):
    template_name = serializers.CharField(source='template.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        model = ReportSchedule
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


class ReportSerializer(serializers.ModelSerializer):
    template_name = serializers.CharField(source='template.name', read_only=True)
    schedule_name = serializers.CharField(source='schedule.name', read_only=True)
    generated_by_name = serializers.CharField(source='generated_by.get_full_name', read_only=True)
    is_expired = serializers.ReadOnlyField()
    file_size_mb = serializers.SerializerMethodField()
    
    class Meta:
        model = Report
        fields = '__all__'
        read_only_fields = ('id', 'generated_at')
    
    def get_file_size_mb(self, obj):
        if obj.file_size:
            return round(obj.file_size / (1024 * 1024), 2)
        return None


class DashboardSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    shared_with_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Dashboard
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_shared_with_count(self, obj):
        return obj.shared_with.count()


class WidgetSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        model = Widget
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


class ReportMetricsSerializer(serializers.ModelSerializer):
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


class AlertRuleSerializer(serializers.ModelSerializer):
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
        recipients = value.get('recipients', [])
        if not isinstance(recipients, list):
            raise serializers.ValidationError("'recipients' must be a list of e-mail addresses.")
        for address in recipients:
            try:
                validate_email(address)
            except (DjangoValidationError, TypeError):
                raise serializers.ValidationError(f"{address!r} is not an e-mail address.")
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
            parse_rule(
                current('data_source'),
                current('condition_type'),
                current('operator'),
                current('threshold_value'),
                current('condition_config', {}),
            )
        except UnsupportedAlertRule as exc:
            raise serializers.ValidationError(exc.args[0])
        return attrs


class AlertNotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertNotification
        fields = (
            'id', 'kind', 'value', 'threshold_value', 'operator', 'recipients',
            'delivered', 'created_at',
        )
        read_only_fields = fields
