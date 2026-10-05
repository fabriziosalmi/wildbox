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
    IMPLEMENTED_DISCOVERY_TYPES,
    Asset, Environment, BusinessFunction, AssetGroup,
    AssetSoftware, AssetPort, AssetDiscoveryRule
)
from .serializers import (
    AssetSerializer, EnvironmentSerializer, BusinessFunctionSerializer,
    AssetGroupSerializer, AssetSoftwareSerializer, AssetPortSerializer,
    AssetDiscoveryRuleSerializer, AssetDetailSerializer
)
from .tasks import discover_assets, scan_asset_ports, update_asset_inventory
from .filters import AssetFilter
from .networks import SCAN_TYPES, NetworkRefused, scan_network
from apps.core.permissions import IsAssetManager, IsGatewayAdminOrReadOnly
from apps.core.tenancy import TeamScopedViewSetMixin, record_team_task


class AssetViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """Asset management viewset"""
    queryset = Asset.objects.select_related(
        'environment', 'business_function', 'owner', 'technical_contact'
    ).prefetch_related('software', 'ports', 'groups')
    serializer_class = AssetSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
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
        """Queue a port scan of this asset's IP address.

        This used to import ``apps.scanners.tasks.scan_asset``, a module that
        has never existed, so every call answered 500 (#537). The scanners
        app records external scanner runs and has no task of its own; the
        scan guardian itself performs is ``scan_asset_ports``, the one an
        asset with an address already gets on creation.
        """
        asset = self.get_object()

        if not asset.ip_address:
            return Response(
                {'error': 'Asset has no IP address to scan'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        task = record_team_task(scan_asset_ports.delay(str(asset.id)), asset.team_id)

        return Response({
            'message': f'Port scan initiated for {asset.name}',
            'task_id': task.id
        })

    @action(detail=True, methods=['post'])
    def add_software(self, request, pk=None):
        """Add software to an asset"""
        asset = self.get_object()
        serializer = AssetSoftwareSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        
        if serializer.is_valid():
            serializer.save(asset=asset)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def add_port(self, request, pk=None):
        """Add port information to an asset"""
        asset = self.get_object()
        serializer = AssetPortSerializer(
            data=request.data, context=self.get_serializer_context()
        )
        
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
        # Checked before anything is queued (#724): a value that is not a
        # network was only found out by the worker, after its retries, and a
        # range of any size was accepted.
        try:
            network = scan_network(request.data.get('network_range'))
        except NetworkRefused as refused:
            return Response(
                {'network_range': [str(refused)]},
                status=status.HTTP_400_BAD_REQUEST
            )
        scan_type = request.data.get('scan_type', 'basic')
        if scan_type not in SCAN_TYPES:
            return Response(
                {'scan_type': [f'One of: {", ".join(SCAN_TYPES)}.']},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Trigger asset discovery task; the hosts it finds are the
        # caller's team's assets (#642).
        team_id = self.get_team_id()
        task = record_team_task(
            discover_assets.delay(str(network), scan_type, team_id=str(team_id)),
            team_id,
        )

        return Response({
            'message': f'Asset discovery initiated for {network}',
            'task_id': task.id
        })

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get asset statistics"""
        # The caller's team's assets only (#642).
        assets = self.team_queryset(Asset)
        stats = {
            'total_assets': assets.count(),
            'by_type': dict(assets.values('asset_type').annotate(count=Count('id')).values_list('asset_type', 'count')),
            'by_criticality': dict(assets.values('criticality').annotate(count=Count('id')).values_list('criticality', 'count')),
            'by_status': dict(assets.values('status').annotate(count=Count('id')).values_list('status', 'count')),
            'recently_discovered': assets.filter(
                first_discovered__gte=timezone.now() - timezone.timedelta(days=7)
            ).count(),
            'with_vulnerabilities': assets.filter(vulnerabilities__isnull=False).distinct().count()
        }
        
        return Response(stats)


class EnvironmentViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """Environment management viewset"""
    queryset = Environment.objects.all()
    serializer_class = EnvironmentSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering = ['name']


class BusinessFunctionViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """Business function management viewset"""
    queryset = BusinessFunction.objects.all()
    serializer_class = BusinessFunctionSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering = ['name']


class AssetGroupViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """Asset group management viewset"""
    queryset = AssetGroup.objects.prefetch_related('assets')
    serializer_class = AssetGroupSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
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
        
        # Only the team's own assets: an id of another team's asset is
        # skipped like an unknown one (#642).
        assets = self.team_queryset(Asset).filter(id__in=asset_ids)
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
        
        assets = self.team_queryset(Asset).filter(id__in=asset_ids)
        group.assets.remove(*assets)
        
        return Response({
            'message': f'Removed {len(assets)} assets from {group.name}',
            'total_assets': group.assets.count()
        })


class AssetDiscoveryRuleViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
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

        # A rule of a type with no implementation (one stored before the
        # API refused them, #548) was queued and answered "executed" with a
        # task id; the task then skipped it (#644).
        if rule.discovery_type not in IMPLEMENTED_DISCOVERY_TYPES:
            return self._not_implemented(rule)

        # Trigger discovery task
        from apps.assets.tasks import execute_discovery_rule
        task = record_team_task(execute_discovery_rule.delay(rule.id), rule.team_id)
        
        return Response({
            'message': f'Discovery rule "{rule.name}" executed',
            'task_id': task.id
        })

    @staticmethod
    def _not_implemented(rule):
        """The answer for what guardian cannot do with a rule of that type."""
        return Response(
            {
                'detail': (
                    f'{rule.discovery_type} discovery is not implemented; '
                    f'supported: {", ".join(IMPLEMENTED_DISCOVERY_TYPES)}.'
                ),
                'code': 'DISCOVERY_TYPE_NOT_IMPLEMENTED',
            },
            status=status.HTTP_501_NOT_IMPLEMENTED,
        )

    @action(detail=True, methods=['post'])
    def enable(self, request, pk=None):
        """Enable a discovery rule"""
        rule = self.get_object()
        # "Enabled" is "runs on its schedule", and a rule of a type with no
        # implementation never runs: it was switched on, answered "enabled"
        # and stayed idle (#724).
        if rule.discovery_type not in IMPLEMENTED_DISCOVERY_TYPES:
            return self._not_implemented(rule)
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


class AssetSoftwareViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """Asset software management viewset"""
    queryset = AssetSoftware.objects.select_related('asset')
    serializer_class = AssetSoftwareSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['asset', 'name', 'vendor', 'is_critical']
    search_fields = ['name', 'vendor', 'version']
    ordering = ['name', 'version']

    @action(detail=False, methods=['get'])
    def inventory(self, request):
        """Get software inventory across all assets"""
        software_summary = self.get_queryset().values(
            'name', 'vendor'
        ).annotate(
            asset_count=Count('asset', distinct=True),
            version_count=Count('version', distinct=True)
        ).order_by('name')
        
        return Response(software_summary)


class AssetPortViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """Asset port management viewset"""
    queryset = AssetPort.objects.select_related('asset')
    serializer_class = AssetPortSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['asset', 'port_number', 'protocol', 'state', 'service']
    search_fields = ['service', 'banner']
    ordering = ['asset__name', 'port_number']

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get port summary across all assets"""
        port_summary = self.get_queryset().filter(
            state='open'
        ).values(
            'port_number', 'protocol', 'service'
        ).annotate(
            asset_count=Count('asset', distinct=True)
        ).order_by('port_number')
        
        return Response(port_summary)
