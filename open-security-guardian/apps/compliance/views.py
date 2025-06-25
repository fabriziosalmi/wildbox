from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from django.db.models import Count, Q
from django.utils import timezone
from .models import (
    ComplianceFramework, ComplianceControl, ComplianceAssessment,
    ComplianceEvidence, ComplianceResult, ComplianceException, ComplianceMetrics
)
from .serializers import (
    ComplianceFrameworkSerializer, ComplianceControlSerializer, ComplianceAssessmentSerializer,
    ComplianceEvidenceSerializer, ComplianceResultSerializer, ComplianceExceptionSerializer,
    ComplianceMetricsSerializer
)
from .filters import (
    ComplianceFrameworkFilter, ComplianceControlFilter, ComplianceAssessmentFilter,
    ComplianceResultFilter, ComplianceExceptionFilter
)


class ComplianceFrameworkViewSet(viewsets.ModelViewSet):
    queryset = ComplianceFramework.objects.all()
    serializer_class = ComplianceFrameworkSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ComplianceFrameworkFilter
    search_fields = ['name', 'description', 'authority']
    ordering_fields = ['name', 'created_at', 'updated_at']
    ordering = ['name']

    @action(detail=True, methods=['get'])
    def controls(self, request, pk=None):
        """Get all controls for a framework"""
        framework = self.get_object()
        controls = framework.controls.all()
        serializer = ComplianceControlSerializer(controls, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def assessments(self, request, pk=None):
        """Get all assessments for a framework"""
        framework = self.get_object()
        assessments = framework.assessments.all()
        serializer = ComplianceAssessmentSerializer(assessments, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def metrics(self, request, pk=None):
        """Get latest metrics for a framework"""
        framework = self.get_object()
        metrics = framework.metrics.order_by('-metric_date').first()
        if metrics:
            serializer = ComplianceMetricsSerializer(metrics)
            return Response(serializer.data)
        return Response({'detail': 'No metrics available'}, status=status.HTTP_404_NOT_FOUND)


class ComplianceControlViewSet(viewsets.ModelViewSet):
    queryset = ComplianceControl.objects.select_related('framework').all()
    serializer_class = ComplianceControlSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ComplianceControlFilter
    search_fields = ['control_id', 'title', 'description']
    ordering_fields = ['control_id', 'title', 'criticality', 'created_at']
    ordering = ['framework', 'control_id']

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        """Get all assessment results for a control"""
        control = self.get_object()
        results = control.results.all()
        serializer = ComplianceResultSerializer(results, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def evidence(self, request, pk=None):
        """Get all evidence for a control"""
        control = self.get_object()
        evidence = control.evidence.all()
        serializer = ComplianceEvidenceSerializer(evidence, many=True)
        return Response(serializer.data)


class ComplianceAssessmentViewSet(viewsets.ModelViewSet):
    queryset = ComplianceAssessment.objects.select_related('framework', 'assessor').prefetch_related('assets').all()
    serializer_class = ComplianceAssessmentSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ComplianceAssessmentFilter
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'status', 'start_date', 'due_date', 'created_at']
    ordering = ['-created_at']

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        """Get all results for an assessment"""
        assessment = self.get_object()
        results = assessment.results.select_related('control').all()
        serializer = ComplianceResultSerializer(results, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def evidence(self, request, pk=None):
        """Get all evidence for an assessment"""
        assessment = self.get_object()
        evidence = assessment.evidence.select_related('control').all()
        serializer = ComplianceEvidenceSerializer(evidence, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def summary(self, request, pk=None):
        """Get compliance summary for an assessment"""
        assessment = self.get_object()
        results = assessment.results.all()
        
        summary = {
            'total_controls': results.count(),
            'compliant': results.filter(status='compliant').count(),
            'non_compliant': results.filter(status='non_compliant').count(),
            'partially_compliant': results.filter(status='partially_compliant').count(),
            'not_applicable': results.filter(status='not_applicable').count(),
            'not_tested': results.filter(status='not_tested').count(),
            'high_risk': results.filter(risk_level='critical').count() + results.filter(risk_level='high').count(),
            'medium_risk': results.filter(risk_level='medium').count(),
            'low_risk': results.filter(risk_level='low').count(),
        }
        
        if summary['total_controls'] > 0:
            summary['compliance_percentage'] = round(
                (summary['compliant'] / summary['total_controls']) * 100, 2
            )
        else:
            summary['compliance_percentage'] = 0
            
        return Response(summary)

    @action(detail=False, methods=['get'])
    def overdue(self, request):
        """Get overdue assessments"""
        overdue_assessments = self.get_queryset().filter(
            due_date__lt=timezone.now(),
            status__in=['planned', 'in_progress']
        )
        serializer = self.get_serializer(overdue_assessments, many=True)
        return Response(serializer.data)


class ComplianceEvidenceViewSet(viewsets.ModelViewSet):
    queryset = ComplianceEvidence.objects.select_related('assessment', 'control', 'collected_by').all()
    serializer_class = ComplianceEvidenceSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['title', 'description']
    ordering_fields = ['title', 'evidence_type', 'collected_at']
    ordering = ['-collected_at']


class ComplianceResultViewSet(viewsets.ModelViewSet):
    queryset = ComplianceResult.objects.select_related('assessment', 'control', 'tested_by', 'reviewed_by').all()
    serializer_class = ComplianceResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ComplianceResultFilter
    search_fields = ['findings', 'recommendations']
    ordering_fields = ['status', 'risk_level', 'tested_at', 'created_at']
    ordering = ['-created_at']

    @action(detail=False, methods=['get'])
    def non_compliant(self, request):
        """Get all non-compliant results"""
        non_compliant = self.get_queryset().filter(
            status__in=['non_compliant', 'partially_compliant']
        )
        serializer = self.get_serializer(non_compliant, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def high_risk(self, request):
        """Get high risk compliance results"""
        high_risk = self.get_queryset().filter(
            risk_level__in=['high', 'critical']
        )
        serializer = self.get_serializer(high_risk, many=True)
        return Response(serializer.data)


class ComplianceExceptionViewSet(viewsets.ModelViewSet):
    queryset = ComplianceException.objects.select_related('control', 'requested_by', 'approved_by').all()
    serializer_class = ComplianceExceptionSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ComplianceExceptionFilter
    search_fields = ['title', 'justification']
    ordering_fields = ['title', 'status', 'valid_until', 'created_at']
    ordering = ['-created_at']

    @action(detail=False, methods=['get'])
    def pending(self, request):
        """Get pending exceptions"""
        pending = self.get_queryset().filter(status='pending')
        serializer = self.get_serializer(pending, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def expiring_soon(self, request):
        """Get exceptions expiring in the next 30 days"""
        from datetime import timedelta
        expiring_soon = self.get_queryset().filter(
            valid_until__lte=timezone.now() + timedelta(days=30),
            status='approved'
        )
        serializer = self.get_serializer(expiring_soon, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def needs_review(self, request):
        """Get exceptions that need review"""
        needs_review = self.get_queryset().filter(
            review_date__lte=timezone.now(),
            status='approved'
        )
        serializer = self.get_serializer(needs_review, many=True)
        return Response(serializer.data)


class ComplianceMetricsViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ComplianceMetrics.objects.select_related('framework', 'assessment').all()
    serializer_class = ComplianceMetricsSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    ordering_fields = ['metric_date', 'compliance_percentage']
    ordering = ['-metric_date']

    @action(detail=False, methods=['get'])
    def dashboard(self, request):
        """Get dashboard metrics"""
        # Get latest metrics for each framework
        frameworks = ComplianceFramework.objects.filter(is_active=True)
        dashboard_data = []
        
        for framework in frameworks:
            latest_metric = framework.metrics.order_by('-metric_date').first()
            if latest_metric:
                dashboard_data.append({
                    'framework': framework.name,
                    'compliance_percentage': latest_metric.compliance_percentage,
                    'total_controls': latest_metric.total_controls,
                    'high_risk_findings': latest_metric.high_risk_findings,
                    'open_exceptions': latest_metric.open_exceptions,
                    'last_updated': latest_metric.metric_date
                })
        
        return Response(dashboard_data)
