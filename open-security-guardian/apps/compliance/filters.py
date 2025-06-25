import django_filters
from django.db.models import Q
from .models import (
    ComplianceFramework, ComplianceControl, ComplianceAssessment,
    ComplianceResult, ComplianceException
)


class ComplianceFrameworkFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(lookup_expr='icontains')
    authority = django_filters.CharFilter(lookup_expr='icontains')
    is_active = django_filters.BooleanFilter()

    class Meta:
        model = ComplianceFramework
        fields = ['name', 'authority', 'is_active']


class ComplianceControlFilter(django_filters.FilterSet):
    framework = django_filters.ModelChoiceFilter(queryset=ComplianceFramework.objects.all())
    control_type = django_filters.ChoiceFilter(choices=ComplianceControl.CONTROL_TYPES)
    criticality = django_filters.ChoiceFilter(choices=ComplianceControl.CRITICALITY_LEVELS)
    control_id = django_filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = ComplianceControl
        fields = ['framework', 'control_type', 'criticality', 'control_id']


class ComplianceAssessmentFilter(django_filters.FilterSet):
    framework = django_filters.ModelChoiceFilter(queryset=ComplianceFramework.objects.all())
    status = django_filters.ChoiceFilter(choices=ComplianceAssessment.STATUS_CHOICES)
    assessment_type = django_filters.ChoiceFilter(choices=ComplianceAssessment.ASSESSMENT_TYPES)
    start_date = django_filters.DateFromToRangeFilter()
    due_date = django_filters.DateFromToRangeFilter()
    is_overdue = django_filters.BooleanFilter(method='filter_overdue')

    class Meta:
        model = ComplianceAssessment
        fields = ['framework', 'status', 'assessment_type', 'start_date', 'due_date']

    def filter_overdue(self, queryset, name, value):
        from django.utils import timezone
        if value:
            return queryset.filter(
                due_date__lt=timezone.now(),
                status__in=['planned', 'in_progress']
            )
        return queryset


class ComplianceResultFilter(django_filters.FilterSet):
    assessment = django_filters.ModelChoiceFilter(queryset=ComplianceAssessment.objects.all())
    control = django_filters.ModelChoiceFilter(queryset=ComplianceControl.objects.all())
    status = django_filters.ChoiceFilter(choices=ComplianceResult.RESULT_STATUS)
    risk_level = django_filters.ChoiceFilter(choices=ComplianceResult.RISK_LEVELS)
    tested_date = django_filters.DateFromToRangeFilter(field_name='tested_at')

    class Meta:
        model = ComplianceResult
        fields = ['assessment', 'control', 'status', 'risk_level']


class ComplianceExceptionFilter(django_filters.FilterSet):
    control = django_filters.ModelChoiceFilter(queryset=ComplianceControl.objects.all())
    status = django_filters.ChoiceFilter(choices=ComplianceException.STATUS_CHOICES)
    valid_until = django_filters.DateFromToRangeFilter()
    is_expired = django_filters.BooleanFilter(method='filter_expired')
    needs_review = django_filters.BooleanFilter(method='filter_needs_review')

    class Meta:
        model = ComplianceException
        fields = ['control', 'status', 'valid_until']

    def filter_expired(self, queryset, name, value):
        from django.utils import timezone
        if value:
            return queryset.filter(valid_until__lt=timezone.now())
        return queryset.filter(valid_until__gte=timezone.now())

    def filter_needs_review(self, queryset, name, value):
        from django.utils import timezone
        if value:
            return queryset.filter(
                review_date__lte=timezone.now(),
                status='approved'
            )
        return queryset
