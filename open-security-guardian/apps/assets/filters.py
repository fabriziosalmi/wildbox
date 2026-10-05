"""
Asset Management Filters

Django filter classes for asset management API endpoints.
"""

import ipaddress

import django_filters
from django.db.models import Q
from rest_framework.exceptions import ValidationError

from .models import Asset, AssetType, AssetCriticality, AssetStatus

#: The most addresses ``ip_range`` lists one by one (see ``network_q``).
MAX_LISTED_ADDRESSES = 256


def network_q(network):
    """The ``Q`` for the addresses inside ``network``, whatever its size.

    The filter used to list every host of the network and ask for
    ``ip_address IN (...)``: ``?ip_range=10.0.0.0/8`` built sixteen million
    strings, and ``0.0.0.0/0`` never answered (#724). An IPv4 address is
    stored in dotted form, so a network that ends on an octet is a text
    prefix (``10.`` for ``10.0.0.0/8``), and any other network is at most
    128 such networks, or at most 128 addresses. Nothing grows with the size
    of the range.

    IPv6 text has no such prefix (``::`` stands for any run of zeros), so an
    IPv6 range is listed, and one of more than MAX_LISTED_ADDRESSES is
    refused by the caller.
    """
    if network.version == 6:
        return Q(ip_address__in=[str(address) for address in network])
    octets = -(-network.prefixlen // 8)
    if octets == 4:
        return Q(ip_address__in=[str(address) for address in network])
    if octets == 0:
        # 0.0.0.0/0: every IPv4 address.
        return Q(ip_address__contains='.') & ~Q(ip_address__contains=':')
    condition = Q()
    for subnet in network.subnets(new_prefix=octets * 8):
        prefix = '.'.join(str(subnet.network_address).split('.')[:octets]) + '.'
        condition |= Q(ip_address__startswith=prefix)
    return condition


class AssetFilter(django_filters.FilterSet):
    """Filter class for Asset model

    ``?search=`` is DRF's SearchFilter over the viewset's ``search_fields``;
    the ``search`` this filter set also had was applied as well (#724).
    """

    # IP address range filtering
    ip_range = django_filters.CharFilter(method='filter_ip_range', label='IP Range')
    
    # Multiple choice filters
    asset_type = django_filters.MultipleChoiceFilter(choices=AssetType.choices)
    criticality = django_filters.MultipleChoiceFilter(choices=AssetCriticality.choices)
    status = django_filters.MultipleChoiceFilter(choices=AssetStatus.choices)
    
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

    def filter_ip_range(self, queryset, name, value):
        """The assets whose address is in a network (CIDR), or starts so.

        A value that is not a network or an address is the start of one:
        ``?ip_range=10.20.`` answers the addresses that begin with it.
        """
        try:
            network = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            return queryset.filter(ip_address__startswith=value.strip())
        if network.version == 6 and network.num_addresses > MAX_LISTED_ADDRESSES:
            raise ValidationError({
                name: [
                    'An IPv6 range of at most '
                    f'{MAX_LISTED_ADDRESSES} addresses (/120 or longer).'
                ]
            })
        return queryset.filter(network_q(network))

    def filter_tags(self, queryset, name, value):
        """The assets that have every one of the comma-separated tags"""
        for tag in value.split(','):
            if tag.strip():
                queryset = queryset.filter(tags__contains=tag.strip())
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
