"""
Asset Management Serializers

Django REST Framework serializers for asset management.
"""

import ipaddress

from rest_framework import serializers

from apps.core.tenancy import (
    TeamScopedModelSerializer,
    context_team_id,
    scope_to_team,
)
from django.contrib.auth.models import User

from apps.core.schedules import InvalidSchedule, schedule_timezone, validate_cron

from .networks import (
    MAX_RULE_NETWORKS, SCAN_TYPES, NetworkRefused, scan_network,
)
from .models import (
    Asset, Environment, BusinessFunction, AssetGroup,
    AssetSoftware, AssetPort, AssetDiscoveryRule, IMPLEMENTED_DISCOVERY_TYPES
)


class EnvironmentSerializer(TeamScopedModelSerializer):
    """Environment serializer"""
    asset_count = serializers.SerializerMethodField()

    class Meta:
        model = Environment
        fields = '__all__'

    def get_asset_count(self, obj):
        """Get count of assets in this environment"""
        return obj.asset_set.count()


class BusinessFunctionSerializer(TeamScopedModelSerializer):
    """Business function serializer"""
    asset_count = serializers.SerializerMethodField()

    class Meta:
        model = BusinessFunction
        fields = '__all__'

    def get_asset_count(self, obj):
        """Get count of assets with this business function"""
        return obj.asset_set.count()


class AssetSoftwareSerializer(TeamScopedModelSerializer):
    """Asset software serializer"""
    
    class Meta:
        model = AssetSoftware
        fields = '__all__'
        read_only_fields = ['asset', 'first_discovered', 'last_verified']


class AssetPortSerializer(TeamScopedModelSerializer):
    """Asset port serializer"""
    
    class Meta:
        model = AssetPort
        fields = '__all__'
        read_only_fields = ['asset', 'first_discovered', 'last_verified']


class AssetSerializer(TeamScopedModelSerializer):
    """Asset serializer for list/create operations"""
    environment_name = serializers.CharField(source='environment.name', read_only=True)
    business_function_name = serializers.CharField(source='business_function.name', read_only=True)
    owner_username = serializers.CharField(source='owner.username', read_only=True)
    technical_contact_username = serializers.CharField(source='technical_contact.username', read_only=True)
    vulnerability_count = serializers.ReadOnlyField()
    risk_score = serializers.ReadOnlyField()
    
    class Meta:
        model = Asset
        fields = [
            'id', 'name', 'description', 'asset_type', 'status',
            'ip_address', 'hostname', 'fqdn', 'mac_address',
            'criticality', 'environment', 'environment_name',
            'business_function', 'business_function_name',
            'owner', 'owner_username', 'technical_contact', 'technical_contact_username',
            'tags', 'metadata', 'discovered_by', 'first_discovered', 'last_seen',
            'created_at', 'updated_at', 'vulnerability_count', 'risk_score'
        ]
        read_only_fields = [
            'id', 'first_discovered', 'last_seen', 'created_at', 'updated_at',
            'vulnerability_count', 'risk_score'
        ]

    def validate_ip_address(self, value):
        """Validate IP address uniqueness within the caller's team.

        Across teams it told a team which addresses another team tracks,
        and stopped it from registering its own host at one (#642).
        """
        if value:
            existing = scope_to_team(
                Asset.objects.filter(ip_address=value), context_team_id(self.context)
            )
            if self.instance:
                existing = existing.exclude(id=self.instance.id)
            if existing.exists():
                raise serializers.ValidationError("An asset with this IP address already exists.")
        return value


class AssetDetailSerializer(AssetSerializer):
    """Detailed asset serializer with related data"""
    software = AssetSoftwareSerializer(many=True, read_only=True)
    ports = AssetPortSerializer(many=True, read_only=True)
    groups = serializers.StringRelatedField(many=True, read_only=True)
    vulnerabilities = serializers.SerializerMethodField()
    
    class Meta(AssetSerializer.Meta):
        fields = AssetSerializer.Meta.fields + ['software', 'ports', 'groups', 'vulnerabilities']

    def get_vulnerabilities(self, obj):
        """Get vulnerability summary for this asset"""
        from apps.vulnerabilities.models import Vulnerability
        vulns = obj.vulnerabilities.filter(status='open')
        return {
            'total': vulns.count(),
            'critical': vulns.filter(severity='critical').count(),
            'high': vulns.filter(severity='high').count(),
            'medium': vulns.filter(severity='medium').count(),
            'low': vulns.filter(severity='low').count(),
        }


class AssetGroupSerializer(TeamScopedModelSerializer):
    """Asset group serializer"""
    asset_count = serializers.SerializerMethodField()
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = AssetGroup
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at']

    def get_asset_count(self, obj):
        """Get count of assets in this group"""
        return obj.assets.count()


class AssetDiscoveryRuleSerializer(TeamScopedModelSerializer):
    """Asset discovery rule serializer"""
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = AssetDiscoveryRule
        fields = '__all__'
        read_only_fields = ['last_run', 'next_run', 'created_at', 'updated_at']

    def validate_target_specification(self, value):
        """Validate target specification format"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Target specification must be a JSON object.")
        
        discovery_type = self.initial_data.get('discovery_type')
        
        if discovery_type is None and self.instance is not None:
            discovery_type = self.instance.discovery_type

        if discovery_type == 'network_scan':
            networks = value.get('networks')
            if not networks or not isinstance(networks, list):
                raise serializers.ValidationError(
                    "Network scan requires 'networks', a list of networks in "
                    "CIDR notation, in target specification."
                )
            if len(networks) > MAX_RULE_NETWORKS:
                raise serializers.ValidationError(
                    f"A rule lists at most {MAX_RULE_NETWORKS} networks."
                )
            for network in networks:
                # What discover_assets would refuse on each run: not a
                # network, or more addresses than one discovery sweeps (#724).
                try:
                    scan_network(network)
                except NetworkRefused as refused:
                    raise serializers.ValidationError(str(refused))
            scan_type = value.get('scan_type', 'basic')
            if scan_type not in SCAN_TYPES:
                raise serializers.ValidationError(
                    f"'scan_type' is one of: {', '.join(SCAN_TYPES)}."
                )
        elif discovery_type == 'cloud_api':
            if 'provider' not in value:
                raise serializers.ValidationError("Cloud API requires 'provider' in target specification.")

        return value

    def validate_discovery_type(self, value):
        """Refuse the discovery types that have no implementation (#548).

        A rule of one of them would be scheduled and "run" without
        discovering anything.
        """
        if value not in IMPLEMENTED_DISCOVERY_TYPES:
            raise serializers.ValidationError(
                f"{value} discovery is not implemented; supported: "
                f"{', '.join(IMPLEMENTED_DISCOVERY_TYPES)}."
            )
        return value

    def validate_schedule(self, value):
        """Five crontab fields that parse and match some time (#548)."""
        try:
            validate_cron(value)
        except InvalidSchedule:
            # A fixed message: the parser's own text is not part of the API.
            raise serializers.ValidationError(
                f"Schedule must be five crontab fields (minute hour "
                f"day-of-month month day-of-week, in {schedule_timezone()}) "
                f"that match at least one time."
            )
        return value
