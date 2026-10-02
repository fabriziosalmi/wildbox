from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from rest_framework import serializers
from .models import (
    ReportTemplate, ReportSchedule, Report, Dashboard, Widget,
    ReportMetrics, AlertRule, SUPPORTED_REPORT_FORMATS, SUPPORTED_REPORT_TYPES
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
        # last_run is when the dispatcher last ran it (#548).
        read_only_fields = ('id', 'created_at', 'updated_at', 'last_run')

    def validate_recipients(self, value):
        """A list of e-mail addresses: they are sent each report (#548)."""
        if not isinstance(value, list):
            raise serializers.ValidationError("Recipients must be a list of e-mail addresses.")
        for address in value:
            try:
                validate_email(address)
            except (DjangoValidationError, TypeError):
                raise serializers.ValidationError(f"{address!r} is not an e-mail address.")
        return value

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
        read_only_fields = ('id', 'created_at', 'updated_at', 'last_triggered', 'trigger_count')
