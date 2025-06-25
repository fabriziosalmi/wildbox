"""
Asset Management Serializers

Django REST Framework serializers for asset management.
"""

from rest_framework import serializers
from django.contrib.auth.models import User

from .models import (
    Asset, Environment, BusinessFunction, AssetGroup,
    AssetSoftware, AssetPort, AssetDiscoveryRule
)


class EnvironmentSerializer(serializers.ModelSerializer):
    """Environment serializer"""
    asset_count = serializers.SerializerMethodField()

    class Meta:
        model = Environment
        fields = '__all__'

    def get_asset_count(self, obj):
        """Get count of assets in this environment"""
        return obj.asset_set.count()


class BusinessFunctionSerializer(serializers.ModelSerializer):
    """Business function serializer"""
    asset_count = serializers.SerializerMethodField()

    class Meta:
        model = BusinessFunction
        fields = '__all__'

    def get_asset_count(self, obj):
        """Get count of assets with this business function"""
        return obj.asset_set.count()


class AssetSoftwareSerializer(serializers.ModelSerializer):
    """Asset software serializer"""
    
    class Meta:
        model = AssetSoftware
        fields = '__all__'
        read_only_fields = ['asset', 'first_discovered', 'last_verified']


class AssetPortSerializer(serializers.ModelSerializer):
    """Asset port serializer"""
    
    class Meta:
        model = AssetPort
        fields = '__all__'
        read_only_fields = ['asset', 'first_discovered', 'last_verified']


class AssetSerializer(serializers.ModelSerializer):
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
        """Validate IP address uniqueness"""
        if value:
            existing = Asset.objects.filter(ip_address=value)
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


class AssetGroupSerializer(serializers.ModelSerializer):
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


class AssetDiscoveryRuleSerializer(serializers.ModelSerializer):
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
        
        if discovery_type == 'network_scan':
            if 'networks' not in value:
                raise serializers.ValidationError("Network scan requires 'networks' in target specification.")
        elif discovery_type == 'cloud_api':
            if 'provider' not in value:
                raise serializers.ValidationError("Cloud API requires 'provider' in target specification.")
        
        return value

    def validate_schedule(self, value):
        """Validate cron schedule format"""
        # Basic cron validation - could be enhanced with croniter
        parts = value.split()
        if len(parts) != 5:
            raise serializers.ValidationError("Schedule must be a valid cron expression (5 fields).")
        return value
