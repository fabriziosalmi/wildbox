"""
Scanner Management Serializers

DRF serializers for scanner-related API endpoints.
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Scanner, ScanProfile, Scan, ScanResult, ScanSchedule,
    ScannerType, ScannerStatus, ScanStatus
)


class ScannerListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for scanner lists"""
    is_healthy = serializers.ReadOnlyField()
    
    class Meta:
        model = Scanner
        fields = [
            'id', 'name', 'scanner_type', 'status', 'is_healthy',
            'last_health_check', 'total_scans_completed',
            'total_vulnerabilities_found', 'created_at'
        ]


class ScannerDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for scanner CRUD operations"""
    is_healthy = serializers.ReadOnlyField()
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        model = Scanner
        fields = '__all__'
        read_only_fields = [
            'total_scans_completed', 'total_vulnerabilities_found',
            'avg_scan_duration_minutes', 'last_health_check', 'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'api_key': {'write_only': True}
        }
    
    def create(self, validated_data):
        """Create scanner with encrypted credentials"""
        # In a real implementation, encrypt sensitive fields
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        """Update scanner with encrypted credentials"""
        # In a real implementation, encrypt sensitive fields
        return super().update(instance, validated_data)


class ScannerConnectionTestSerializer(serializers.Serializer):
    """Serializer for testing scanner connections"""
    success = serializers.BooleanField()
    message = serializers.CharField()
    response_time_ms = serializers.IntegerField(required=False)
    scanner_version = serializers.CharField(required=False)
    error_details = serializers.CharField(required=False)


class ScanProfileSerializer(serializers.ModelSerializer):
    """Serializer for scan profiles"""
    scanner_name = serializers.CharField(source='scanner.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        model = ScanProfile
        fields = '__all__'
        read_only_fields = ['times_used', 'avg_scan_time_minutes', 'created_at', 'updated_at']


class ScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for scan lists"""
    scanner_name = serializers.CharField(source='scanner.name', read_only=True)
    profile_name = serializers.CharField(source='profile.name', read_only=True)
    duration_formatted = serializers.ReadOnlyField()
    is_active = serializers.ReadOnlyField()
    target_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = [
            'id', 'name', 'scanner_name', 'profile_name', 'status',
            'scheduled_start', 'started_at', 'completed_at', 'duration_formatted',
            'is_active', 'progress_percentage', 'target_count',
            'total_vulnerabilities_found', 'critical_count', 'high_count'
        ]
    
    def get_target_count(self, obj):
        """Get number of target assets"""
        return obj.target_assets.count() + len(obj.target_ranges)


class ScanDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for scan CRUD operations"""
    scanner_name = serializers.CharField(source='scanner.name', read_only=True)
    profile_name = serializers.CharField(source='profile.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    duration_formatted = serializers.ReadOnlyField()
    is_active = serializers.ReadOnlyField()
    risk_score = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = '__all__'
        read_only_fields = [
            'scanner_scan_id', 'started_at', 'completed_at', 'duration_seconds',
            'total_hosts_scanned', 'total_vulnerabilities_found',
            'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count',
            'progress_percentage', 'current_host', 'error_message', 'retry_count',
            'created_at', 'updated_at'
        ]
    
    def get_risk_score(self, obj):
        """Calculate risk score for the scan"""
        return obj.calculate_risk_score()


class ScanCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new scans"""
    
    class Meta:
        model = Scan
        fields = [
            'name', 'description', 'scanner', 'profile',
            'target_assets', 'target_ranges', 'scheduled_start',
            'recurrence_pattern', 'scan_settings'
        ]
    
    def validate_target_ranges(self, value):
        """Validate target IP ranges"""
        if not value and not self.initial_data.get('target_assets'):
            raise serializers.ValidationError(
                "Either target_assets or target_ranges must be provided"
            )
        
        # Validate IP ranges format
        for target in value:
            if not isinstance(target, str):
                raise serializers.ValidationError(
                    "Target ranges must be strings (IP addresses or hostnames)"
                )
        
        return value


class ScanResultSerializer(serializers.ModelSerializer):
    """Serializer for individual scan results"""
    asset_name = serializers.CharField(source='asset.name', read_only=True)
    risk_score = serializers.ReadOnlyField()
    
    class Meta:
        model = ScanResult
        fields = '__all__'
        read_only_fields = [
            'processed', 'vulnerability_created', 'vulnerability', 'created_at'
        ]


class ScanResultSummarySerializer(serializers.Serializer):
    """Serializer for scan result summaries"""
    total_results = serializers.IntegerField()
    critical_count = serializers.IntegerField()
    high_count = serializers.IntegerField()
    medium_count = serializers.IntegerField()
    low_count = serializers.IntegerField()
    info_count = serializers.IntegerField()
    
    processed_count = serializers.IntegerField()
    vulnerabilities_created = serializers.IntegerField()
    
    top_affected_hosts = serializers.ListField(child=serializers.DictField())
    common_vulnerabilities = serializers.ListField(child=serializers.DictField())


class ScanScheduleSerializer(serializers.ModelSerializer):
    """Serializer for recurring scan schedules"""
    scanner_name = serializers.CharField(source='scanner.name', read_only=True)
    profile_name = serializers.CharField(source='profile.name', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        model = ScanSchedule
        fields = '__all__'
        read_only_fields = [
            'next_run', 'last_run', 'total_runs', 'successful_runs',
            'failed_runs', 'created_at', 'updated_at'
        ]
    
    def validate_cron_expression(self, value):
        """Validate cron expression format"""
        # Basic cron validation - in real implementation use a proper cron library
        parts = value.split()
        if len(parts) != 5:
            raise serializers.ValidationError(
                "Cron expression must have 5 parts: minute hour day month weekday"
            )
        return value


class ScanControlSerializer(serializers.Serializer):
    """Serializer for scan control actions"""
    action = serializers.ChoiceField(choices=[
        ('start', 'Start'),
        ('pause', 'Pause'),
        ('resume', 'Resume'),
        ('cancel', 'Cancel'),
        ('retry', 'Retry')
    ])
    reason = serializers.CharField(max_length=500, required=False)


class ScanImportSerializer(serializers.Serializer):
    """Serializer for importing scan results"""
    file_format = serializers.ChoiceField(choices=[
        ('nessus', 'Nessus (.nessus)'),
        ('qualys', 'Qualys XML'),
        ('openvas', 'OpenVAS XML'),
        ('csv', 'CSV'),
        ('json', 'JSON')
    ])
    file_content = serializers.CharField(help_text="Base64 encoded file content")
    create_vulnerabilities = serializers.BooleanField(default=True)
    assign_to_assets = serializers.BooleanField(default=True)


class ScannerStatsSerializer(serializers.Serializer):
    """Serializer for scanner statistics"""
    total_scanners = serializers.IntegerField()
    active_scanners = serializers.IntegerField()
    inactive_scanners = serializers.IntegerField()
    error_scanners = serializers.IntegerField()
    
    total_scans = serializers.IntegerField()
    running_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    failed_scans = serializers.IntegerField()
    
    total_vulnerabilities_found = serializers.IntegerField()
    avg_scan_duration_minutes = serializers.FloatField()
    
    scanner_types = serializers.DictField()
    scan_frequency = serializers.DictField()


class ScannerHealthSerializer(serializers.Serializer):
    """Serializer for scanner health status"""
    scanner_id = serializers.UUIDField()
    scanner_name = serializers.CharField()
    is_healthy = serializers.BooleanField()
    last_check = serializers.DateTimeField()
    status = serializers.CharField()
    error_message = serializers.CharField(required=False)
    response_time_ms = serializers.IntegerField(required=False)


class BulkScanActionSerializer(serializers.Serializer):
    """Serializer for bulk scan actions"""
    scan_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
        max_length=50
    )
    action = serializers.ChoiceField(choices=[
        ('start', 'Start'),
        ('pause', 'Pause'),
        ('cancel', 'Cancel'),
        ('delete', 'Delete')
    ])
    reason = serializers.CharField(max_length=500, required=False)
    
    def validate_scan_ids(self, value):
        """Validate that all scan IDs exist"""
        existing_scans = Scan.objects.filter(id__in=value).count()
        if existing_scans != len(value):
            raise serializers.ValidationError(
                f"Some scan IDs are invalid. Found {existing_scans} out of {len(value)} scans."
            )
        return value
