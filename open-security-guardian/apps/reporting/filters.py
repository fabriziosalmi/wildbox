import django_filters
from django.db.models import Q
from .models import (
    ReportTemplate, ReportSchedule, Report, Dashboard, Widget, AlertRule
)


class ReportTemplateFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(lookup_expr='icontains')
    report_type = django_filters.ChoiceFilter(choices=ReportTemplate.REPORT_TYPES)
    is_active = django_filters.BooleanFilter()
    is_public = django_filters.BooleanFilter()

    class Meta:
        model = ReportTemplate
        fields = ['name', 'report_type', 'is_active', 'is_public']


class ReportScheduleFilter(django_filters.FilterSet):
    template = django_filters.ModelChoiceFilter(queryset=ReportTemplate.objects.all())
    frequency = django_filters.ChoiceFilter(choices=ReportSchedule.FREQUENCY_CHOICES)
    status = django_filters.ChoiceFilter(choices=ReportSchedule.STATUS_CHOICES)
    next_run = django_filters.DateFromToRangeFilter()

    class Meta:
        model = ReportSchedule
        fields = ['template', 'frequency', 'status', 'next_run']


class ReportFilter(django_filters.FilterSet):
    template = django_filters.ModelChoiceFilter(queryset=ReportTemplate.objects.all())
    schedule = django_filters.ModelChoiceFilter(queryset=ReportSchedule.objects.all())
    status = django_filters.ChoiceFilter(choices=Report.STATUS_CHOICES)
    format = django_filters.ChoiceFilter(choices=ReportTemplate.FORMAT_CHOICES)
    generated_date = django_filters.DateFromToRangeFilter(field_name='generated_at')
    is_expired = django_filters.BooleanFilter(method='filter_expired')

    class Meta:
        model = Report
        fields = ['template', 'schedule', 'status', 'format']

    def filter_expired(self, queryset, name, value):
        from django.utils import timezone
        if value:
            return queryset.filter(expires_at__lt=timezone.now())
        return queryset.filter(
            Q(expires_at__isnull=True) | Q(expires_at__gte=timezone.now())
        )


class DashboardFilter(django_filters.FilterSet):
    dashboard_type = django_filters.ChoiceFilter(choices=Dashboard.DASHBOARD_TYPES)
    is_active = django_filters.BooleanFilter()
    is_public = django_filters.BooleanFilter()

    class Meta:
        model = Dashboard
        fields = ['dashboard_type', 'is_active', 'is_public']


class WidgetFilter(django_filters.FilterSet):
    widget_type = django_filters.ChoiceFilter(choices=Widget.WIDGET_TYPES)
    chart_type = django_filters.ChoiceFilter(choices=Widget.CHART_TYPES)
    data_source = django_filters.CharFilter(lookup_expr='icontains')
    is_active = django_filters.BooleanFilter()

    class Meta:
        model = Widget
        fields = ['widget_type', 'chart_type', 'data_source', 'is_active']


class AlertRuleFilter(django_filters.FilterSet):
    condition_type = django_filters.ChoiceFilter(choices=AlertRule.CONDITION_TYPES)
    operator = django_filters.ChoiceFilter(choices=AlertRule.OPERATORS)
    is_active = django_filters.BooleanFilter()
    data_source = django_filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = AlertRule
        fields = ['condition_type', 'operator', 'is_active', 'data_source']
