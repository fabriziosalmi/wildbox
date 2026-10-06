"""
Vulnerability Management Serializers

DRF serializers for vulnerability-related API endpoints.
"""

from rest_framework import serializers

from apps.core.tenancy import TeamScopedModelSerializer
from django.contrib.auth.models import User
from .models import (
    Vulnerability, VulnerabilityTemplate, VulnerabilityAssessment,
    VulnerabilityHistory
)


class VulnerabilityListSerializer(TeamScopedModelSerializer):
    """Lightweight serializer for vulnerability lists"""
    asset_name = serializers.CharField(source='asset.name', read_only=True)
    asset_type = serializers.CharField(source='asset.asset_type', read_only=True)
    days_to_due = serializers.ReadOnlyField()
    is_overdue = serializers.ReadOnlyField()
    
    class Meta:
        model = Vulnerability
        fields = [
            'id', 'title', 'cve_id', 'severity', 'status', 'priority',
            'risk_score', 'cvss_v3_score', 'asset_name', 'asset_type',
            'due_date', 'days_to_due', 'is_overdue', 'created_at', 'updated_at'
        ]


class VulnerabilityDetailSerializer(TeamScopedModelSerializer):
    """Detailed serializer for vulnerability CRUD operations"""
    asset_name = serializers.CharField(source='asset.name', read_only=True)
    asset_details = serializers.SerializerMethodField()
    assigned_to_name = serializers.CharField(source='assigned_to.get_full_name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    days_to_due = serializers.ReadOnlyField()
    is_overdue = serializers.ReadOnlyField()
    
    class Meta:
        model = Vulnerability
        fields = '__all__'
        read_only_fields = ['risk_score', 'first_discovered', 'created_at', 'updated_at']
    
    def get_asset_details(self, obj):
        """Get basic asset information"""
        environment = obj.asset.environment
        return {
            'id': obj.asset.id,
            'name': obj.asset.name,
            'asset_type': obj.asset.asset_type,
            'criticality': obj.asset.criticality,
            'ip_address': obj.asset.ip_address,
            # Its name. This was the Environment row itself, which is not
            # JSON: the record of a vulnerability whose asset has an
            # environment answered 500 (#724).
            'environment': environment.name if environment else None,
        }


class VulnerabilityCreateSerializer(TeamScopedModelSerializer):
    """Serializer for creating new vulnerabilities"""
    
    class Meta:
        model = Vulnerability
        # With the id: the answer to a creation did not say what had been
        # created, so a client had to search the list for it (#724).
        fields = [
            'id', 'title', 'description', 'cve_id', 'asset', 'severity',
            'cvss_v3_score', 'cvss_v3_vector', 'threat_level',
            'exploitability_score', 'business_impact_score',
            'port', 'protocol', 'service', 'plugin_id',
            'evidence', 'solution', 'references', 'scanner',
            'scan_id', 'assigned_to', 'assignee_group', 'priority',
            'tags', 'metadata'
        ]
        # A finding does not have to be a CVE. The model says so
        # (blank=True); DRF made the field required all the same, because it
        # is part of the unique set (asset, cve_id, port), and a request
        # without it answered 400 (#724).
        extra_kwargs = {'cve_id': {'required': False, 'default': ''}}

    def validate(self, attrs):
        """One finding for an asset and a CVE without a port, too (#775).

        The unique set (asset, cve_id, port) did not hold when ``port`` was
        omitted: DRF's validator skips a set with a None in it, and the
        database's unique index takes two NULLs for two values, on SQLite
        and on PostgreSQL. So a second finding for the same asset and CVE
        answered 201, where one with a port answers 400.

        A finding that is not a CVE (``cve_id`` empty) and has no port is
        left alone: guardian has nothing to tell two of them apart by, and
        an asset has more than one misconfiguration.
        """
        attrs = super().validate(attrs)
        if (
            attrs.get('port') is None
            and attrs.get('cve_id')
            and Vulnerability.objects.filter(
                asset=attrs['asset'], cve_id=attrs['cve_id'], port__isnull=True
            ).exists()
        ):
            # The answer a duplicate with a port gets, from DRF's validator.
            raise serializers.ValidationError(
                "The fields asset, cve_id, port must make a unique set.",
                code='unique',
            )
        return attrs

    def validate_cvss_v3_score(self, value):
        """Validate CVSS score is within valid range"""
        if value is not None and (value < 0.0 or value > 10.0):
            raise serializers.ValidationError("CVSS score must be between 0.0 and 10.0")
        return value


class VulnerabilityUpdateSerializer(TeamScopedModelSerializer):
    """Serializer for updating vulnerabilities"""
    
    class Meta:
        model = Vulnerability
        fields = [
            'title', 'description', 'severity', 'status', 'priority',
            'cvss_v3_score', 'cvss_v3_vector', 'threat_level',
            'exploitability_score', 'business_impact_score',
            'evidence', 'solution', 'references', 'assigned_to',
            'assignee_group', 'due_date', 'tags', 'metadata'
        ]
        read_only_fields = ['risk_score']


class VulnerabilityTemplateSerializer(TeamScopedModelSerializer):
    """Serializer for vulnerability templates"""
    
    class Meta:
        model = VulnerabilityTemplate
        fields = '__all__'


class VulnerabilityAssessmentSerializer(TeamScopedModelSerializer):
    """Serializer for vulnerability risk assessments"""
    
    class Meta:
        model = VulnerabilityAssessment
        fields = '__all__'


class VulnerabilityHistorySerializer(TeamScopedModelSerializer):
    """Serializer for vulnerability history tracking"""
    changed_by_name = serializers.CharField(source='changed_by.get_full_name', read_only=True)
    
    class Meta:
        model = VulnerabilityHistory
        fields = '__all__'
        read_only_fields = ['timestamp', 'changed_by']


class VulnerabilityBulkActionSerializer(serializers.Serializer):
    """Serializer for bulk vulnerability actions"""
    vulnerability_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
        max_length=100
    )
    action = serializers.ChoiceField(choices=[
        ('close', 'Close'),
        ('reopen', 'Reopen'),
        ('assign', 'Assign'),
        ('tag', 'Add Tag'),
        ('untag', 'Remove Tag'),
        ('priority', 'Change Priority')
    ])
    
    # Optional fields based on action
    assigned_to = serializers.IntegerField(required=False)
    assignee_group = serializers.CharField(max_length=100, required=False)
    tag = serializers.CharField(max_length=50, required=False)
    priority = serializers.ChoiceField(
        choices=[('p1', 'P1'), ('p2', 'P2'), ('p3', 'P3'), ('p4', 'P4')],
        required=False
    )
    reason = serializers.CharField(max_length=500, required=False)
    
    def validate(self, data):
        """Validate action-specific fields"""
        action = data.get('action')
        
        if action == 'assign' and not data.get('assigned_to') and not data.get('assignee_group'):
            raise serializers.ValidationError(
                "Either 'assigned_to' or 'assignee_group' is required for assign action"
            )
        
        if action in ['tag', 'untag'] and not data.get('tag'):
            raise serializers.ValidationError("'tag' field is required for tag actions")
        
        if action == 'priority' and not data.get('priority'):
            raise serializers.ValidationError("'priority' field is required for priority action")
        
        return data


class VulnerabilityStatsSerializer(serializers.Serializer):
    """Serializer for vulnerability statistics"""
    total_vulnerabilities = serializers.IntegerField()
    critical_count = serializers.IntegerField()
    high_count = serializers.IntegerField()
    medium_count = serializers.IntegerField()
    low_count = serializers.IntegerField()
    info_count = serializers.IntegerField()
    
    open_count = serializers.IntegerField()
    in_progress_count = serializers.IntegerField()
    resolved_count = serializers.IntegerField()
    
    overdue_count = serializers.IntegerField()
    due_today_count = serializers.IntegerField()
    due_this_week_count = serializers.IntegerField()
    
    avg_risk_score = serializers.FloatField()
    avg_resolution_time_days = serializers.FloatField()


class VulnerabilityTrendSerializer(serializers.Serializer):
    """Serializer for vulnerability trends over time"""
    date = serializers.DateField()
    discovered_count = serializers.IntegerField()
    resolved_count = serializers.IntegerField()
    total_open = serializers.IntegerField()
    avg_risk_score = serializers.FloatField()
