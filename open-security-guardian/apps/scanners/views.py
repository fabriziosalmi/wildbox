"""
Scanner Management Views

Django REST Framework views for scanner management.
"""

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from .models import Scanner, ScanProfile, Scan, ScanResult, ScanSchedule
from .serializers import (
    ScannerListSerializer, ScannerDetailSerializer, ScannerConnectionTestSerializer,
    ScanProfileSerializer, ScanListSerializer, ScanDetailSerializer,
    ScanCreateSerializer, ScanResultSerializer, ScanScheduleSerializer,
    ScanControlSerializer, ScanImportSerializer, ScannerStatsSerializer
)


class ScannerViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scanners"""
    queryset = Scanner.objects.all()
    permission_classes = [permissions.IsAuthenticated]
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

    @action(detail=True, methods=['post'])
    def test_connection(self, request, pk=None):
        """Test connection to scanner"""
        scanner = self.get_object()
        serializer = ScannerConnectionTestSerializer(data=request.data)
        if serializer.is_valid():
            # TODO: Implement actual connection test logic
            return Response({'status': 'success', 'message': 'Connection test passed'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get scanner statistics"""
        total_scanners = Scanner.objects.count()
        active_scanners = Scanner.objects.filter(status='active').count()
        data = {
            'total_scanners': total_scanners,
            'active_scanners': active_scanners,
            'inactive_scanners': total_scanners - active_scanners
        }
        serializer = ScannerStatsSerializer(data)
        return Response(serializer.data)


class ScanProfileViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scan profiles"""
    queryset = ScanProfile.objects.all()
    serializer_class = ScanProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description']
    filterset_fields = ['scanner']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']


class ScanViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scans"""
    queryset = Scan.objects.all()
    permission_classes = [permissions.IsAuthenticated]
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

    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start a scan"""
        scan = self.get_object()
        serializer = ScanControlSerializer(data=request.data)
        if serializer.is_valid():
            # TODO: Implement actual scan start logic
            scan.status = 'running'
            scan.save()
            return Response({'status': 'success', 'message': 'Scan started'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def stop(self, request, pk=None):
        """Stop a scan"""
        scan = self.get_object()
        # TODO: Implement actual scan stop logic
        scan.status = 'stopped'
        scan.save()
        return Response({'status': 'success', 'message': 'Scan stopped'})

    @action(detail=True, methods=['post'])
    def pause(self, request, pk=None):
        """Pause a scan"""
        scan = self.get_object()
        # TODO: Implement actual scan pause logic
        scan.status = 'paused'
        scan.save()
        return Response({'status': 'success', 'message': 'Scan paused'})

    @action(detail=True, methods=['post'])
    def resume(self, request, pk=None):
        """Resume a scan"""
        scan = self.get_object()
        # TODO: Implement actual scan resume logic
        scan.status = 'running'
        scan.save()
        return Response({'status': 'success', 'message': 'Scan resumed'})

    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        """Get scan results"""
        scan = self.get_object()
        results = ScanResult.objects.filter(scan=scan)
        serializer = ScanResultSerializer(results, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def import_results(self, request):
        """Import scan results from external source"""
        serializer = ScanImportSerializer(data=request.data)
        if serializer.is_valid():
            # TODO: Implement actual import logic
            return Response({'status': 'success', 'message': 'Results imported'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScanResultViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scan results"""
    queryset = ScanResult.objects.all()
    serializer_class = ScanResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['plugin_name', 'description', 'host']
    filterset_fields = ['scan', 'severity', 'processed', 'vulnerability_created']
    ordering_fields = ['created_at', 'severity', 'cvss_base_score']
    ordering = ['-created_at']


class ScanScheduleViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scan schedules"""
    queryset = ScanSchedule.objects.all()
    serializer_class = ScanScheduleSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description']
    filterset_fields = ['scanner', 'is_active']
    ordering_fields = ['name', 'created_at', 'next_run']
    ordering = ['next_run']

    @action(detail=True, methods=['post'])
    def trigger(self, request, pk=None):
        """Manually trigger a scheduled scan"""
        schedule = self.get_object()
        # TODO: Implement actual schedule trigger logic
        return Response({'status': 'success', 'message': 'Schedule triggered'})

    @action(detail=True, methods=['post'])
    def enable(self, request, pk=None):
        """Enable a scan schedule"""
        schedule = self.get_object()
        schedule.is_active = True
        schedule.save()
        return Response({'status': 'success', 'message': 'Schedule enabled'})

    @action(detail=True, methods=['post'])
    def disable(self, request, pk=None):
        """Disable a scan schedule"""
        schedule = self.get_object()
        schedule.is_active = False
        schedule.save()
        return Response({'status': 'success', 'message': 'Schedule disabled'})
