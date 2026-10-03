from rest_framework import serializers

from apps.core.tenancy import TeamScopedModelSerializer
from .models import (
    ComplianceFramework, ComplianceControl, ComplianceAssessment,
    ComplianceEvidence, ComplianceResult, ComplianceException, ComplianceMetrics
)


class ComplianceFrameworkSerializer(TeamScopedModelSerializer):
    controls_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ComplianceFramework
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_controls_count(self, obj):
        return obj.controls.count()


class ComplianceControlSerializer(TeamScopedModelSerializer):
    framework_name = serializers.CharField(source='framework.name', read_only=True)
    
    class Meta:
        model = ComplianceControl
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


class ComplianceAssessmentSerializer(TeamScopedModelSerializer):
    framework_name = serializers.CharField(source='framework.name', read_only=True)
    assessor_name = serializers.CharField(source='assessor.get_full_name', read_only=True)
    assets_count = serializers.SerializerMethodField()
    is_overdue = serializers.ReadOnlyField()
    
    class Meta:
        model = ComplianceAssessment
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_assets_count(self, obj):
        return obj.assets.count()


class ComplianceEvidenceSerializer(TeamScopedModelSerializer):
    assessment_name = serializers.CharField(source='assessment.name', read_only=True)
    control_id = serializers.CharField(source='control.control_id', read_only=True)
    collected_by_name = serializers.CharField(source='collected_by.get_full_name', read_only=True)
    
    class Meta:
        model = ComplianceEvidence
        fields = '__all__'
        read_only_fields = ('id', 'collected_at')


class ComplianceResultSerializer(TeamScopedModelSerializer):
    assessment_name = serializers.CharField(source='assessment.name', read_only=True)
    control_id = serializers.CharField(source='control.control_id', read_only=True)
    control_title = serializers.CharField(source='control.title', read_only=True)
    tested_by_name = serializers.CharField(source='tested_by.get_full_name', read_only=True)
    reviewed_by_name = serializers.CharField(source='reviewed_by.get_full_name', read_only=True)
    
    class Meta:
        model = ComplianceResult
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


class ComplianceExceptionSerializer(TeamScopedModelSerializer):
    control_id = serializers.CharField(source='control.control_id', read_only=True)
    control_title = serializers.CharField(source='control.title', read_only=True)
    requested_by_name = serializers.CharField(source='requested_by.get_full_name', read_only=True)
    approved_by_name = serializers.CharField(source='approved_by.get_full_name', read_only=True)
    is_expired = serializers.ReadOnlyField()
    needs_review = serializers.ReadOnlyField()
    
    class Meta:
        model = ComplianceException
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


class ComplianceMetricsSerializer(TeamScopedModelSerializer):
    framework_name = serializers.CharField(source='framework.name', read_only=True)
    assessment_name = serializers.CharField(source='assessment.name', read_only=True)
    
    class Meta:
        model = ComplianceMetrics
        fields = '__all__'
        read_only_fields = ('id', 'created_at')
