"""
Scanner Management Views

Django REST Framework views for scanner management.

These viewsets keep records of external scanners (Nessus, Qualys, OpenVAS,
Rapid7, custom) and of their runs. guardian has no code that talks to one:
``scanners/{id}/test_connection``, ``scans/{id}/start``, ``stop``, ``pause``
and ``resume`` and ``scans/import_results`` answered "success" having
contacted nothing and imported nothing (the first asked the caller for a
``success`` flag and answered "Connection test passed" whatever it was), and
were removed (#644). A scan's ``status``
is a field of the record, set with PUT or PATCH like the others. The scan
guardian itself performs is the asset port scan (apps.assets).
"""

from rest_framework import viewsets, status
from apps.core.permissions import IsGatewayAdminOrReadOnly
from apps.core.tenancy import TeamScopedViewSetMixin
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from datetime import timedelta

from django.db.models import Avg, Count, Sum
from django.utils import timezone

from .models import (
    Scan, ScanProfile, ScanResult, ScanSchedule, ScanStatus, Scanner, ScannerStatus,
)
from .serializers import (
    ScannerListSerializer, ScannerDetailSerializer,
    ScanProfileSerializer, ScanListSerializer, ScanDetailSerializer,
    ScanCreateSerializer, ScanResultSerializer, ScanScheduleSerializer,
    ScannerStatsSerializer
)


class ScannerViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing scanners"""
    queryset = Scanner.objects.all()
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description', 'scanner_type']
    filterset_fields = ['scanner_type', 'status']
    ordering_fields = ['name', 'created_at', 'last_health_check']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action in ['list']:
            return ScannerListSerializer
        elif self.action in ['retrieve']:
            return ScannerDetailSerializer
        return ScannerDetailSerializer

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get scanner statistics"""
        # ScannerStatsSerializer declares every field below as required on
        # output; returning only the scanner counts made it raise KeyError
        # and the endpoint answered 500.
        now = timezone.now()
        # The caller's team's scanners and scans only (#642).
        scanners = self.team_queryset(Scanner)
        total_scanners = scanners.count()
        active_scanners = scanners.filter(status=ScannerStatus.ACTIVE).count()
        scans = self.team_queryset(Scan)
        data = {
            'total_scanners': total_scanners,
            'active_scanners': active_scanners,
            'inactive_scanners': total_scanners - active_scanners,
            'error_scanners': scanners.filter(status=ScannerStatus.ERROR).count(),
            'total_scans': scans.count(),
            'running_scans': scans.filter(status=ScanStatus.RUNNING).count(),
            'completed_scans': scans.filter(status=ScanStatus.COMPLETED).count(),
            'failed_scans': scans.filter(status=ScanStatus.FAILED).count(),
            'total_vulnerabilities_found': scans.aggregate(
                total=Sum('total_vulnerabilities_found')
            )['total'] or 0,
            'avg_scan_duration_minutes': (
                scans.filter(duration_seconds__isnull=False).aggregate(
                    avg=Avg('duration_seconds')
                )['avg'] or 0
            ) / 60,
            'scanner_types': dict(
                scanners.values_list('scanner_type')
                .annotate(n=Count('id'))
                .order_by()
            ),
            'scan_frequency': {
                'last_24h': scans.filter(created_at__gte=now - timedelta(days=1)).count(),
                'last_7d': scans.filter(created_at__gte=now - timedelta(days=7)).count(),
                'last_30d': scans.filter(created_at__gte=now - timedelta(days=30)).count(),
            },
        }
        serializer = ScannerStatsSerializer(data)
        return Response(serializer.data)


class ScanProfileViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing scan profiles"""
    queryset = ScanProfile.objects.all()
    serializer_class = ScanProfileSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description']
    filterset_fields = ['scanner']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']


class ScanViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing scans"""
    queryset = Scan.objects.all()
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description']
    filterset_fields = ['scanner', 'profile', 'status']
    ordering_fields = ['created_at', 'started_at', 'completed_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action in ['list']:
            return ScanListSerializer
        elif self.action in ['create']:
            return ScanCreateSerializer
        elif self.action in ['retrieve']:
            return ScanDetailSerializer
        return ScanDetailSerializer

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        """Get scan results"""
        scan = self.get_object()
        results = ScanResult.objects.filter(scan=scan)
        serializer = ScanResultSerializer(results, many=True)
        return Response(serializer.data)


class ScanResultViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing scan results"""
    queryset = ScanResult.objects.all()
    serializer_class = ScanResultSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['plugin_name', 'description', 'host']
    filterset_fields = ['scan', 'severity', 'processed', 'vulnerability_created']
    ordering_fields = ['created_at', 'severity', 'cvss_base_score']
    ordering = ['-created_at']


SCAN_SCHEDULES_UNSUPPORTED = (
    "Scheduled scans are not supported: guardian cannot start a scan on an "
    "external scanner yet (starting, stopping and importing scans are not "
    "implemented), so a schedule would never run. Existing schedules can be "
    "listed, disabled and deleted."
)


class ScanScheduleViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing scan schedules.

    A scan schedule names an external scanner (Nessus, Qualys, OpenVAS,
    Rapid7 or a custom one) and a scan profile, and guardian has no code
    that starts a scan on any of them (the start, stop, pause, resume and
    import actions that pretended to were removed, #644). The asset port scan
    (apps.assets.tasks.scan_asset_ports) is guardian's own TCP connect scan
    of one asset; it uses neither the scanner nor the profile and produces
    no Scan or ScanResult, so running it for a scan schedule would report
    work that was not done. Creating, changing, triggering and enabling a
    schedule therefore answer 400 instead of accepting a schedule nothing
    would run (#548).
    """
    queryset = ScanSchedule.objects.all()
    serializer_class = ScanScheduleSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description']
    filterset_fields = ['scanner', 'is_active']
    ordering_fields = ['name', 'created_at', 'next_run']
    ordering = ['next_run']

    @staticmethod
    def _unsupported():
        return Response(
            {'detail': SCAN_SCHEDULES_UNSUPPORTED},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def create(self, request, *args, **kwargs):
        return self._unsupported()

    def update(self, request, *args, **kwargs):
        # PATCH goes through here too (partial_update calls update).
        self.get_object()
        return self._unsupported()

    @action(detail=True, methods=['post'])
    def trigger(self, request, pk=None):
        """Manually trigger a scheduled scan: not supported (#548)."""
        self.get_object()
        return self._unsupported()

    @action(detail=True, methods=['post'])
    def enable(self, request, pk=None):
        """Enable a scan schedule: not supported (#548)."""
        self.get_object()
        return self._unsupported()

    @action(detail=True, methods=['post'])
    def disable(self, request, pk=None):
        """Disable a scan schedule"""
        schedule = self.get_object()
        schedule.is_active = False
        schedule.save()
        return Response({'status': 'success', 'message': 'Schedule disabled'})
