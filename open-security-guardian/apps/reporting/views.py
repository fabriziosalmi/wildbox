import logging
from rest_framework import viewsets, status, permissions
from apps.core.permissions import IsGatewayAdminOrReadOnly
from apps.core.tenancy import TeamScopedViewSetMixin, record_team_task
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from django.db.models import Count, Q, Avg, Sum
from django.utils import timezone
from django.http import HttpResponse, Http404
from .models import (
    ReportTemplate, ReportSchedule, Report, Dashboard, Widget,
    ReportMetrics, AlertRule
)
from .serializers import (
    ReportTemplateSerializer, ReportScheduleSerializer, ReportSerializer,
    DashboardSerializer, WidgetSerializer, ReportMetricsSerializer,
    AlertRuleSerializer, AlertNotificationSerializer
)
from .filters import (
    ReportTemplateFilter, ReportScheduleFilter, ReportFilter,
    DashboardFilter, WidgetFilter, AlertRuleFilter
)
from .tasks import generate_report, process_widget_data, report_file_is_served
import os

logger = logging.getLogger(__name__)


class ReportTemplateViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    queryset = ReportTemplate.objects.all()
    serializer_class = ReportTemplateSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ReportTemplateFilter
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'report_type', 'created_at']
    ordering = ['name']

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def generate(self, request, pk=None):
        """Generate a report from this template"""
        template = self.get_object()
        parameters = request.data.get('parameters', {})
        filters = request.data.get('filters', {})
        format = request.data.get('format', template.default_format)
        
        # Create report record
        report = Report.objects.create(
            name=f"{template.name} - {timezone.now().strftime('%Y-%m-%d %H:%M')}",
            template=template,
            format=format,
            parameters=parameters,
            filters=filters,
            generated_by=request.user
        )
        
        # Queue report generation
        generate_report.delay(report.id)
        
        serializer = ReportSerializer(
            report, context=self.get_serializer_context()
        )
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=['get'])
    def reports(self, request, pk=None):
        """Get all reports generated from this template"""
        template = self.get_object()
        reports = template.reports.all()
        serializer = ReportSerializer(
            reports, many=True, context=self.get_serializer_context()
        )
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def metrics(self, request, pk=None):
        """Get metrics for this template"""
        template = self.get_object()
        metrics = template.metrics.order_by('-metric_date')[:30]  # Last 30 days
        serializer = ReportMetricsSerializer(
            metrics, many=True, context=self.get_serializer_context()
        )
        return Response(serializer.data)


class ReportScheduleViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    queryset = ReportSchedule.objects.select_related('template', 'created_by').all()
    serializer_class = ReportScheduleSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ReportScheduleFilter
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'frequency', 'next_run', 'created_at']
    ordering = ['next_run']

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def run_now(self, request, pk=None):
        """Run a scheduled report immediately"""
        schedule = self.get_object()
        
        # Create report record
        report = Report.objects.create(
            name=f"{schedule.name} - {timezone.now().strftime('%Y-%m-%d %H:%M')}",
            template=schedule.template,
            schedule=schedule,
            format=schedule.format,
            parameters=schedule.parameters,
            filters=schedule.filters,
            generated_by=request.user
        )
        
        # Queue report generation
        generate_report.delay(report.id)
        
        serializer = ReportSerializer(
            report, context=self.get_serializer_context()
        )
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

    @action(detail=False, methods=['get'])
    def due(self, request):
        """Get schedules that are due to run"""
        due_schedules = self.get_queryset().filter(
            next_run__lte=timezone.now(),
            status='active'
        )
        serializer = self.get_serializer(due_schedules, many=True)
        return Response(serializer.data)


class ReportViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    queryset = Report.objects.select_related('template', 'schedule', 'generated_by').all()
    serializer_class = ReportSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ReportFilter
    search_fields = ['name']
    ordering_fields = ['name', 'status', 'generated_at']
    ordering = ['-generated_at']

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """Download a generated report"""
        report = self.get_object()
        
        if report.status != 'completed':
            return Response(
                {'detail': 'Report is not ready for download'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not report.file_path or not os.path.exists(report.file_path):
            return Response(
                {'detail': 'Report file not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # The row is the caller's team's (get_object); serve its file only
        # from where generate_report writes reports, never a path a row
        # could have been pointed at elsewhere (#642).
        if not report_file_is_served(report.file_path, report.template.team_id):
            logger.warning("Report %s points outside the reports directory", report.pk)
            return Response(
                {'detail': 'Report file not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Serve file
        with open(report.file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{report.name}.{report.format}"'
            return response

    @action(detail=False, methods=['get'])
    def recent(self, request):
        """Get recent reports"""
        recent_reports = self.get_queryset()[:20]
        serializer = self.get_serializer(recent_reports, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def failed(self, request):
        """Get failed reports"""
        failed_reports = self.get_queryset().filter(status='failed')
        serializer = self.get_serializer(failed_reports, many=True)
        return Response(serializer.data)


class DashboardViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    queryset = Dashboard.objects.prefetch_related('shared_with').all()
    serializer_class = DashboardSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = DashboardFilter
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'dashboard_type', 'created_at']
    ordering = ['name']

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def get_queryset(self):
        """The team's dashboards that are public in it, or the caller's own.

        ``super()`` narrows them to the caller's team first: "public" means
        public to the team (#642).
        """
        user = self.request.user
        return super().get_queryset().filter(
            Q(is_public=True) |
            Q(created_by=user) |
            Q(shared_with=user)
        ).distinct()

    @action(detail=True, methods=['get'])
    def data(self, request, pk=None):
        """Get dashboard data"""
        dashboard = self.get_object()
        
        # Process each widget
        widgets_data = []
        for widget_config in dashboard.widgets_config:
            widget_data = process_widget_data(
                widget_config, dashboard.filters_config, team_id=dashboard.team_id
            )
            widgets_data.append(widget_data)
        
        return Response({
            'dashboard': DashboardSerializer(
                dashboard, context=self.get_serializer_context()
            ).data,
            'widgets': widgets_data,
            'last_updated': timezone.now().isoformat()
        })

    @action(detail=True, methods=['post'])
    def share(self, request, pk=None):
        """Share dashboard with users"""
        dashboard = self.get_object()
        user_ids = request.data.get('user_ids', [])
        
        # Add users to shared_with: members of the caller's team only (#642)
        from django.contrib.auth.models import User
        users = self.team_queryset(User).filter(id__in=user_ids)
        dashboard.shared_with.add(*users)
        
        return Response({'detail': f'Dashboard shared with {len(users)} users'})


class WidgetViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    queryset = Widget.objects.all()
    serializer_class = WidgetSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = WidgetFilter
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'widget_type', 'created_at']
    ordering = ['name']

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['get'])
    def data(self, request, pk=None):
        """Get widget data"""
        widget = self.get_object()
        filters = request.query_params.dict()
        
        data = process_widget_data(widget, filters, team_id=widget.team_id)
        return Response(data)

    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """Test widget configuration"""
        widget = self.get_object()
        test_filters = request.data.get('filters', {})
        
        try:
            data = process_widget_data(widget, test_filters, team_id=widget.team_id)
            return Response({
                'status': 'success',
                'data': data
            })
        except Exception:
            # Log the cause; return a generic message. str(e) exposed
            # internal details (queries, field names, paths) to the caller.
            logger.exception("Widget test failed for widget %s", widget.pk)
            return Response({
                'status': 'error',
                'error': 'The widget could not be evaluated with these filters.'
            }, status=status.HTTP_400_BAD_REQUEST)


class ReportMetricsViewSet(TeamScopedViewSetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = ReportMetrics.objects.select_related('template').all()
    serializer_class = ReportMetricsSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    ordering_fields = ['metric_date', 'generation_count', 'success_rate']
    ordering = ['-metric_date']

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get overall reporting metrics summary"""
        from datetime import timedelta
        
        # Get metrics for the last 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)
        recent_metrics = self.get_queryset().filter(metric_date__gte=thirty_days_ago)
        
        summary = {
            'total_reports_generated': recent_metrics.aggregate(
                total=Sum('generation_count')
            )['total'] or 0,
            'average_success_rate': recent_metrics.aggregate(
                avg=Avg('success_rate')
            )['avg'] or 0,
            'most_popular_templates': recent_metrics.values('template__name').annotate(
                total_count=Sum('generation_count')
            ).order_by('-total_count')[:5],
            'total_storage_used_mb': sum([
                m.total_file_size / (1024 * 1024) for m in recent_metrics if m.total_file_size
            ])
        }
        
        return Response(summary)


class AlertRuleViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    queryset = AlertRule.objects.all()
    serializer_class = AlertRuleSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = AlertRuleFilter
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'condition_type', 'last_triggered', 'created_at']
    ordering = ['name']

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """Test an alert rule"""
        rule = self.get_object()
        
        # Test the rule condition
        from .tasks import check_alert_rule
        result = check_alert_rule(rule.id, test_mode=True)
        
        return Response({
            'rule_triggered': result.get('triggered', False),
            'current_value': result.get('current_value'),
            'threshold_value': rule.threshold_value,
            'test_time': timezone.now().isoformat()
        })

    @action(detail=True, methods=['get'])
    def notifications(self, request, pk=None):
        """The notifications this rule sent, newest first (#549)."""
        rule = self.get_object()
        page = self.paginate_queryset(rule.notifications.all())
        serializer = AlertNotificationSerializer(
            page, many=True, context=self.get_serializer_context()
        )
        return self.get_paginated_response(serializer.data)

    @action(detail=False, methods=['post'])
    def check_all(self, request):
        """Check all active alert rules"""
        from .tasks import check_all_alert_rules
        
        # The caller's team's rules only (#642).
        team_id = self.get_team_id()
        task = record_team_task(
            check_all_alert_rules.delay(team_id=str(team_id)), team_id
        )
        return Response({
            'task_id': task.id,
            'message': 'Alert rule check initiated'
        })
