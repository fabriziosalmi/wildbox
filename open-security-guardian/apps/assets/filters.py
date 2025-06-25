"""
Asset Management Filters

Django filter classes for asset management API endpoints.
"""

import django_filters
from django.db.models import Q

from .models import Asset, AssetSoftware, AssetPort


class AssetFilter(django_filters.FilterSet):
    """Filter class for Asset model"""
    
    # Text search across multiple fields
    search = django_filters.CharFilter(method='filter_search', label='Search')
    
    # IP address range filtering
    ip_range = django_filters.CharFilter(method='filter_ip_range', label='IP Range')
    
    # Multiple choice filters
    asset_type = django_filters.MultipleChoiceFilter(choices=Asset.AssetType.choices)
    criticality = django_filters.MultipleChoiceFilter(choices=Asset.AssetCriticality.choices)
    status = django_filters.MultipleChoiceFilter(choices=Asset.AssetStatus.choices)
    
    # Foreign key filters
    environment = django_filters.CharFilter(field_name='environment__name', lookup_expr='icontains')
    business_function = django_filters.CharFilter(field_name='business_function__name', lookup_expr='icontains')
    owner = django_filters.CharFilter(field_name='owner__username', lookup_expr='icontains')
    
    # Tag filtering
    tags = django_filters.CharFilter(method='filter_tags', label='Tags')
    
    # Date range filters
    discovered_after = django_filters.DateTimeFilter(field_name='first_discovered', lookup_expr='gte')
    discovered_before = django_filters.DateTimeFilter(field_name='first_discovered', lookup_expr='lte')
    last_seen_after = django_filters.DateTimeFilter(field_name='last_seen', lookup_expr='gte')
    last_seen_before = django_filters.DateTimeFilter(field_name='last_seen', lookup_expr='lte')
    
    # Boolean filters
    has_vulnerabilities = django_filters.BooleanFilter(method='filter_has_vulnerabilities')
    has_software = django_filters.BooleanFilter(method='filter_has_software')
    has_open_ports = django_filters.BooleanFilter(method='filter_has_open_ports')
    
    class Meta:
        model = Asset
        fields = []

    def filter_search(self, queryset, name, value):
        """Search across multiple text fields"""
        return queryset.filter(
            Q(name__icontains=value) |
            Q(hostname__icontains=value) |
            Q(fqdn__icontains=value) |
            Q(ip_address__icontains=value) |
            Q(description__icontains=value)
        )

    def filter_ip_range(self, queryset, name, value):
        """Filter by IP address range (CIDR notation)"""
        try:
            import ipaddress
            network = ipaddress.ip_network(value, strict=False)
            return queryset.filter(
                ip_address__in=[str(ip) for ip in network.hosts()]
            )
        except (ValueError, ipaddress.AddressValueError):
            # If invalid CIDR, treat as partial IP match
            return queryset.filter(ip_address__startswith=value)

    def filter_tags(self, queryset, name, value):
        """Filter by tags (comma-separated)"""
        tags = [tag.strip() for tag in value.split(',')]
        for tag in tags:
            queryset = queryset.filter(tags__contains=tag)
        return queryset

    def filter_has_vulnerabilities(self, queryset, name, value):
        """Filter assets with/without vulnerabilities"""
        if value:
            return queryset.filter(vulnerabilities__isnull=False).distinct()
        else:
            return queryset.filter(vulnerabilities__isnull=True)

    def filter_has_software(self, queryset, name, value):
        """Filter assets with/without software inventory"""
        if value:
            return queryset.filter(software__isnull=False).distinct()
        else:
            return queryset.filter(software__isnull=True)

    def filter_has_open_ports(self, queryset, name, value):
        """Filter assets with/without open ports"""
        if value:
            return queryset.filter(ports__state='open').distinct()
        else:
            return queryset.exclude(ports__state='open').distinct()


class AssetSoftwareFilter(django_filters.FilterSet):
    """Filter class for AssetSoftware model"""
    
    asset_name = django_filters.CharFilter(field_name='asset__name', lookup_expr='icontains')
    asset_ip = django_filters.CharFilter(field_name='asset__ip_address')
    name = django_filters.CharFilter(lookup_expr='icontains')
    vendor = django_filters.CharFilter(lookup_expr='icontains')
    version = django_filters.CharFilter(lookup_expr='icontains')
    is_critical = django_filters.BooleanFilter()
    
    class Meta:
        model = AssetSoftware
        fields = []


class AssetPortFilter(django_filters.FilterSet):
    """Filter class for AssetPort model"""
    
    asset_name = django_filters.CharFilter(field_name='asset__name', lookup_expr='icontains')
    asset_ip = django_filters.CharFilter(field_name='asset__ip_address')
    port_number = django_filters.NumberFilter()
    port_range = django_filters.CharFilter(method='filter_port_range')
    protocol = django_filters.ChoiceFilter(choices=[('tcp', 'TCP'), ('udp', 'UDP')])
    state = django_filters.ChoiceFilter(choices=[
        ('open', 'Open'), ('closed', 'Closed'), 
        ('filtered', 'Filtered'), ('unknown', 'Unknown')
    ])
    service = django_filters.CharFilter(lookup_expr='icontains')
    
    class Meta:
        model = AssetPort
        fields = []

    def filter_port_range(self, queryset, name, value):
        """Filter by port range (e.g., '80-443')"""
        try:
            if '-' in value:
                start, end = map(int, value.split('-', 1))
                return queryset.filter(port_number__gte=start, port_number__lte=end)
            else:
                return queryset.filter(port_number=int(value))
        except (ValueError, TypeError):
            return queryset.none()
