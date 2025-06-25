"""
Asset Management API Views

RESTful API endpoints for asset management operations.
"""

from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q, Count
from django.utils import timezone

from .models import (
    Asset, Environment, BusinessFunction, AssetGroup, 
    AssetSoftware, AssetPort, AssetDiscoveryRule
)
from .serializers import (
    AssetSerializer, EnvironmentSerializer, BusinessFunctionSerializer,
    AssetGroupSerializer, AssetSoftwareSerializer, AssetPortSerializer,
    AssetDiscoveryRuleSerializer, AssetDetailSerializer
)
from .tasks import discover_assets, update_asset_inventory
from .filters import AssetFilter
from apps.core.permissions import IsAssetManager


class AssetViewSet(viewsets.ModelViewSet):
    """Asset management viewset"""
    queryset = Asset.objects.select_related(
        'environment', 'business_function', 'owner', 'technical_contact'
    ).prefetch_related('software', 'ports', 'groups')
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = AssetFilter
    search_fields = ['name', 'hostname', 'fqdn', 'ip_address', 'description']
    ordering_fields = ['name', 'criticality', 'last_seen', 'created_at']
    ordering = ['-last_seen']

    def get_serializer_class(self):
        """Return detailed serializer for retrieve action"""
        if self.action == 'retrieve':
            return AssetDetailSerializer
        return AssetSerializer

    def perform_create(self, serializer):
        """Set the created_by field to the current user"""
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def scan(self, request, pk=None):
        """Trigger a vulnerability scan for this asset"""
        asset = self.get_object()
        
        # Trigger vulnerability scan task
        from apps.scanners.tasks import scan_asset
        task = scan_asset.delay(asset.id)
        
        return Response({
            'message': f'Vulnerability scan initiated for {asset.name}',
            'task_id': task.id
        })

    @action(detail=True, methods=['post'])
    def add_software(self, request, pk=None):
        """Add software to an asset"""
        asset = self.get_object()
        serializer = AssetSoftwareSerializer(data=request.data)
        
        if serializer.is_valid():
            serializer.save(asset=asset)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def add_port(self, request, pk=None):
        """Add port information to an asset"""
        asset = self.get_object()
        serializer = AssetPortSerializer(data=request.data)
        
        if serializer.is_valid():
            serializer.save(asset=asset)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def add_tag(self, request, pk=None):
        """Add a tag to an asset"""
        asset = self.get_object()
        tag = request.data.get('tag')
        
        if not tag:
            return Response({'error': 'Tag is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        asset.add_tag(tag)
        return Response({'message': f'Tag "{tag}" added to {asset.name}'})

    @action(detail=True, methods=['delete'])
    def remove_tag(self, request, pk=None):
        """Remove a tag from an asset"""
        asset = self.get_object()
        tag = request.data.get('tag')
        
        if not tag:
            return Response({'error': 'Tag is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        asset.remove_tag(tag)
        return Response({'message': f'Tag "{tag}" removed from {asset.name}'})

    @action(detail=False, methods=['post'])
    def discover(self, request):
        """Initiate asset discovery"""
        network_range = request.data.get('network_range')
        scan_type = request.data.get('scan_type', 'basic')
        
        if not network_range:
            return Response({'error': 'Network range is required'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        
        # Trigger asset discovery task
        task = discover_assets.delay(network_range, scan_type)
        
        return Response({
            'message': f'Asset discovery initiated for {network_range}',
            'task_id': task.id
        })

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get asset statistics"""
        stats = {
            'total_assets': Asset.objects.count(),
            'by_type': dict(Asset.objects.values('asset_type').annotate(count=Count('id')).values_list('asset_type', 'count')),
            'by_criticality': dict(Asset.objects.values('criticality').annotate(count=Count('id')).values_list('criticality', 'count')),
            'by_status': dict(Asset.objects.values('status').annotate(count=Count('id')).values_list('status', 'count')),
            'recently_discovered': Asset.objects.filter(
                first_discovered__gte=timezone.now() - timezone.timedelta(days=7)
            ).count(),
            'with_vulnerabilities': Asset.objects.filter(vulnerabilities__isnull=False).distinct().count()
        }
        
        return Response(stats)


class EnvironmentViewSet(viewsets.ModelViewSet):
    """Environment management viewset"""
    queryset = Environment.objects.all()
    serializer_class = EnvironmentSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering = ['name']


class BusinessFunctionViewSet(viewsets.ModelViewSet):
    """Business function management viewset"""
    queryset = BusinessFunction.objects.all()
    serializer_class = BusinessFunctionSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering = ['name']


class AssetGroupViewSet(viewsets.ModelViewSet):
    """Asset group management viewset"""
    queryset = AssetGroup.objects.prefetch_related('assets')
    serializer_class = AssetGroupSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering = ['name']

    def perform_create(self, serializer):
        """Set the created_by field to the current user"""
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def apply_rules(self, request, pk=None):
        """Apply auto-assignment rules to the group"""
        group = self.get_object()
        group.apply_auto_assignment_rules()
        
        return Response({
            'message': f'Auto-assignment rules applied to {group.name}',
            'asset_count': group.assets.count()
        })

    @action(detail=True, methods=['post'])
    def add_assets(self, request, pk=None):
        """Add assets to the group"""
        group = self.get_object()
        asset_ids = request.data.get('asset_ids', [])
        
        if not asset_ids:
            return Response({'error': 'Asset IDs are required'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        
        assets = Asset.objects.filter(id__in=asset_ids)
        group.assets.add(*assets)
        
        return Response({
            'message': f'Added {len(assets)} assets to {group.name}',
            'total_assets': group.assets.count()
        })

    @action(detail=True, methods=['delete'])
    def remove_assets(self, request, pk=None):
        """Remove assets from the group"""
        group = self.get_object()
        asset_ids = request.data.get('asset_ids', [])
        
        if not asset_ids:
            return Response({'error': 'Asset IDs are required'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        
        assets = Asset.objects.filter(id__in=asset_ids)
        group.assets.remove(*assets)
        
        return Response({
            'message': f'Removed {len(assets)} assets from {group.name}',
            'total_assets': group.assets.count()
        })


class AssetDiscoveryRuleViewSet(viewsets.ModelViewSet):
    """Asset discovery rule management viewset"""
    queryset = AssetDiscoveryRule.objects.all()
    serializer_class = AssetDiscoveryRuleSerializer
    permission_classes = [IsAuthenticated, IsAssetManager]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering = ['name']

    def perform_create(self, serializer):
        """Set the created_by field to the current user"""
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """Execute a discovery rule immediately"""
        rule = self.get_object()
        
        if not rule.enabled:
            return Response({'error': 'Discovery rule is disabled'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        
        # Trigger discovery task
        from apps.assets.tasks import execute_discovery_rule
        task = execute_discovery_rule.delay(rule.id)
        
        return Response({
            'message': f'Discovery rule "{rule.name}" executed',
            'task_id': task.id
        })

    @action(detail=True, methods=['post'])
    def enable(self, request, pk=None):
        """Enable a discovery rule"""
        rule = self.get_object()
        rule.enabled = True
        rule.save()
        
        return Response({'message': f'Discovery rule "{rule.name}" enabled'})

    @action(detail=True, methods=['post'])
    def disable(self, request, pk=None):
        """Disable a discovery rule"""
        rule = self.get_object()
        rule.enabled = False
        rule.save()
        
        return Response({'message': f'Discovery rule "{rule.name}" disabled'})


class AssetSoftwareViewSet(viewsets.ModelViewSet):
    """Asset software management viewset"""
    queryset = AssetSoftware.objects.select_related('asset')
    serializer_class = AssetSoftwareSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['asset', 'name', 'vendor', 'is_critical']
    search_fields = ['name', 'vendor', 'version']
    ordering = ['name', 'version']

    @action(detail=False, methods=['get'])
    def inventory(self, request):
        """Get software inventory across all assets"""
        software_summary = AssetSoftware.objects.values(
            'name', 'vendor'
        ).annotate(
            asset_count=Count('asset', distinct=True),
            version_count=Count('version', distinct=True)
        ).order_by('name')
        
        return Response(software_summary)


class AssetPortViewSet(viewsets.ModelViewSet):
    """Asset port management viewset"""
    queryset = AssetPort.objects.select_related('asset')
    serializer_class = AssetPortSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['asset', 'port_number', 'protocol', 'state', 'service']
    search_fields = ['service', 'banner']
    ordering = ['asset__name', 'port_number']

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get port summary across all assets"""
        port_summary = AssetPort.objects.filter(
            state='open'
        ).values(
            'port_number', 'protocol', 'service'
        ).annotate(
            asset_count=Count('asset', distinct=True)
        ).order_by('port_number')
        
        return Response(port_summary)
