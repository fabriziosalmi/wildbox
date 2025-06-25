"""
Vulnerability Management Filters

Django-filter filters for vulnerability filtering and search.
"""

import django_filters
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta

from .models import Vulnerability, VulnerabilityStatus, VulnerabilitySeverity, ThreatLevel


class VulnerabilityFilter(django_filters.FilterSet):
    """Filter set for vulnerability queries"""
    
    # Text search
    search = django_filters.CharFilter(method='filter_search', label='Search')
    
    # Status filters
    status = django_filters.MultipleChoiceFilter(
        choices=VulnerabilityStatus.choices,
        field_name='status',
        lookup_expr='in'
    )
    
    # Severity filters
    severity = django_filters.MultipleChoiceFilter(
        choices=VulnerabilitySeverity.choices,
        field_name='severity',
        lookup_expr='in'
    )
    
    # Risk score range
    risk_score_min = django_filters.NumberFilter(
        field_name='risk_score',
        lookup_expr='gte',
        label='Minimum Risk Score'
    )
    risk_score_max = django_filters.NumberFilter(
        field_name='risk_score',
        lookup_expr='lte',
        label='Maximum Risk Score'
    )
    
    # CVSS score range
    cvss_min = django_filters.NumberFilter(
        field_name='cvss_v3_score',
        lookup_expr='gte',
        label='Minimum CVSS Score'
    )
    cvss_max = django_filters.NumberFilter(
        field_name='cvss_v3_score',
        lookup_expr='lte',
        label='Maximum CVSS Score'
    )
    
    # Asset filters
    asset_id = django_filters.UUIDFilter(field_name='asset__id')
    asset_name = django_filters.CharFilter(
        field_name='asset__name',
        lookup_expr='icontains',
        label='Asset Name'
    )
    asset_type = django_filters.CharFilter(
        field_name='asset__asset_type',
        lookup_expr='iexact',
        label='Asset Type'
    )
    asset_criticality = django_filters.CharFilter(
        field_name='asset__criticality',
        lookup_expr='iexact',
        label='Asset Criticality'
    )
    asset_environment = django_filters.CharFilter(
        field_name='asset__environment',
        lookup_expr='iexact',
        label='Environment'
    )
    
    # Assignment filters
    assigned_to = django_filters.NumberFilter(
        field_name='assigned_to__id',
        label='Assigned To User ID'
    )
    assignee_group = django_filters.CharFilter(
        field_name='assignee_group',
        lookup_expr='icontains',
        label='Assignee Group'
    )
    unassigned = django_filters.BooleanFilter(
        method='filter_unassigned',
        label='Unassigned'
    )
    
    # Priority filters
    priority = django_filters.MultipleChoiceFilter(
        choices=[
            ('p1', 'P1 - Emergency'),
            ('p2', 'P2 - High'),
            ('p3', 'P3 - Medium'),
            ('p4', 'P4 - Low')
        ],
        field_name='priority',
        lookup_expr='in'
    )
    
    # Threat level filters
    threat_level = django_filters.MultipleChoiceFilter(
        choices=ThreatLevel.choices,
        field_name='threat_level',
        lookup_expr='in'
    )
    
    # Date filters
    discovered_after = django_filters.DateTimeFilter(
        field_name='first_discovered',
        lookup_expr='gte',
        label='Discovered After'
    )
    discovered_before = django_filters.DateTimeFilter(
        field_name='first_discovered',
        lookup_expr='lte',
        label='Discovered Before'
    )
    
    # Due date filters
    due_date_from = django_filters.DateTimeFilter(
        field_name='due_date',
        lookup_expr='gte',
        label='Due Date From'
    )
    due_date_to = django_filters.DateTimeFilter(
        field_name='due_date',
        lookup_expr='lte',
        label='Due Date To'
    )
    
    # Special filters
    overdue = django_filters.BooleanFilter(
        method='filter_overdue',
        label='Overdue'
    )
    due_today = django_filters.BooleanFilter(
        method='filter_due_today',
        label='Due Today'
    )
    due_this_week = django_filters.BooleanFilter(
        method='filter_due_this_week',
        label='Due This Week'
    )
    
    # CVE filter
    cve_id = django_filters.CharFilter(
        field_name='cve_id',
        lookup_expr='icontains',
        label='CVE ID'
    )
    
    # Scanner filters
    scanner = django_filters.CharFilter(
        field_name='scanner',
        lookup_expr='icontains',
        label='Scanner'
    )
    
    # Tag filters
    has_tag = django_filters.CharFilter(
        method='filter_has_tag',
        label='Has Tag'
    )
    
    # Port and service filters
    port = django_filters.NumberFilter(field_name='port')
    service = django_filters.CharFilter(
        field_name='service',
        lookup_expr='icontains',
        label='Service'
    )
    protocol = django_filters.CharFilter(
        field_name='protocol',
        lookup_expr='iexact',
        label='Protocol'
    )
    
    class Meta:
        model = Vulnerability
        fields = []
    
    def filter_search(self, queryset, name, value):
        """Global search across multiple fields"""
        if not value:
            return queryset
        
        return queryset.filter(
            Q(title__icontains=value) |
            Q(description__icontains=value) |
            Q(cve_id__icontains=value) |
            Q(asset__name__icontains=value) |
            Q(asset__ip_address__icontains=value) |
            Q(scanner__icontains=value) |
            Q(service__icontains=value)
        )
    
    def filter_unassigned(self, queryset, name, value):
        """Filter for unassigned vulnerabilities"""
        if value:
            return queryset.filter(
                Q(assigned_to__isnull=True) & 
                Q(assignee_group__isnull=True)
            )
        return queryset
    
    def filter_overdue(self, queryset, name, value):
        """Filter for overdue vulnerabilities"""
        if value:
            return queryset.filter(
                due_date__lt=timezone.now(),
                status=VulnerabilityStatus.OPEN
            )
        return queryset
    
    def filter_due_today(self, queryset, name, value):
        """Filter for vulnerabilities due today"""
        if value:
            today = timezone.now().date()
            return queryset.filter(
                due_date__date=today,
                status=VulnerabilityStatus.OPEN
            )
        return queryset
    
    def filter_due_this_week(self, queryset, name, value):
        """Filter for vulnerabilities due this week"""
        if value:
            now = timezone.now()
            week_end = now + timedelta(weeks=1)
            return queryset.filter(
                due_date__range=(now, week_end),
                status=VulnerabilityStatus.OPEN
            )
        return queryset
    
    def filter_has_tag(self, queryset, name, value):
        """Filter for vulnerabilities with specific tag"""
        if not value:
            return queryset
        
        return queryset.filter(tags__contains=[value])


class VulnerabilityDateRangeFilter(django_filters.FilterSet):
    """Specialized filter for date range queries"""
    
    date_range = django_filters.DateFromToRangeFilter(
        field_name='first_discovered',
        label='Discovery Date Range'
    )
    
    resolution_date_range = django_filters.DateFromToRangeFilter(
        field_name='resolved_at',
        label='Resolution Date Range'
    )
    
    class Meta:
        model = Vulnerability
        fields = ['date_range', 'resolution_date_range']


class VulnerabilityRiskFilter(django_filters.FilterSet):
    """Specialized filter for risk-based queries"""
    
    high_risk = django_filters.BooleanFilter(
        method='filter_high_risk',
        label='High Risk (Score >= 7.0)'
    )
    
    critical_assets = django_filters.BooleanFilter(
        method='filter_critical_assets',
        label='Critical Assets Only'
    )
    
    active_threats = django_filters.BooleanFilter(
        method='filter_active_threats',
        label='Active Threat Intelligence'
    )
    
    class Meta:
        model = Vulnerability
        fields = []
    
    def filter_high_risk(self, queryset, name, value):
        """Filter for high risk vulnerabilities"""
        if value:
            return queryset.filter(risk_score__gte=7.0)
        return queryset
    
    def filter_critical_assets(self, queryset, name, value):
        """Filter for vulnerabilities on critical assets"""
        if value:
            return queryset.filter(asset__criticality='critical')
        return queryset
    
    def filter_active_threats(self, queryset, name, value):
        """Filter for vulnerabilities with active threat intelligence"""
        if value:
            return queryset.filter(
                threat_level__in=[ThreatLevel.IMMINENT, ThreatLevel.ACTIVE]
            )
        return queryset
