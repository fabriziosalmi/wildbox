"""
Vulnerability Management Filters

Django-filter filters for vulnerability filtering and search.
"""

import django_filters
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta

from apps.core.filters import either

from .models import Vulnerability, VulnerabilityStatus, VulnerabilitySeverity, ThreatLevel


class VulnerabilityFilter(django_filters.FilterSet):
    """Filter set for vulnerability queries

    ``?search=`` is not here: it is DRF's SearchFilter over the viewset's
    ``search_fields``. A second ``search`` in this filter set was applied as
    well, so a row had to match both (#724).
    """

    # The choice filters take one value or several (``?severity=high`` or
    # ``?severity=high&severity=critical``) and answer the rows that have any
    # of them. They carry no ``lookup_expr``: a MultipleChoiceFilter compares
    # the column with each value in turn, so with ``lookup_expr='in'`` it
    # asked for ``severity IN ('h', 'i', 'g', 'h')``, the characters of the
    # value, and no row ever matched (#724).

    # Status filters
    status = django_filters.MultipleChoiceFilter(
        choices=VulnerabilityStatus.choices,
        field_name='status',
    )

    # Severity filters
    severity = django_filters.MultipleChoiceFilter(
        choices=VulnerabilitySeverity.choices,
        field_name='severity',
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
    # By the environment's name. ``asset__environment`` is the foreign key,
    # which has no ``iexact``: every request that used the filter answered
    # 500 (#724).
    asset_environment = django_filters.CharFilter(
        field_name='asset__environment__name',
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
        choices=Vulnerability._meta.get_field('priority').choices,
        field_name='priority',
    )

    # Threat level filters
    threat_level = django_filters.MultipleChoiceFilter(
        choices=ThreatLevel.choices,
        field_name='threat_level',
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
    
    # A true/false filter answers the rows that are so for ``true`` and the
    # others for ``false``. ``false`` answered every row, as if the filter
    # had not been given (#724).

    def filter_unassigned(self, queryset, name, value):
        """Vulnerabilities assigned to nobody: no user and no group.

        ``assignee_group`` is a string, empty when there is no group and
        never NULL: compared with NULL, nothing was ever unassigned (#724).
        """
        return either(
            queryset, value, Q(assigned_to__isnull=True) & Q(assignee_group='')
        )

    def filter_overdue(self, queryset, name, value):
        """Open vulnerabilities whose due date has passed"""
        return either(
            queryset,
            value,
            Q(due_date__lt=timezone.now(), status=VulnerabilityStatus.OPEN),
        )

    def filter_due_today(self, queryset, name, value):
        """Open vulnerabilities due today"""
        today = timezone.now().date()
        return either(
            queryset, value, Q(due_date__date=today, status=VulnerabilityStatus.OPEN)
        )

    def filter_due_this_week(self, queryset, name, value):
        """Open vulnerabilities due within the next seven days"""
        now = timezone.now()
        return either(
            queryset,
            value,
            Q(
                due_date__range=(now, now + timedelta(weeks=1)),
                status=VulnerabilityStatus.OPEN,
            ),
        )

    def filter_has_tag(self, queryset, name, value):
        """Filter for vulnerabilities with specific tag"""
        if not value:
            return queryset

        return queryset.filter(tags__contains=[value])
