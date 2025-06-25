"""
Vulnerability Management Views

DRF ViewSets and API views for vulnerability management.
"""

from django.shortcuts import get_object_or_404
from django.db.models import Q, Count, Avg, F, Case, When, IntegerField
from django.utils import timezone
from django.contrib.auth.models import User
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from datetime import timedelta, datetime

from .models import (
    Vulnerability, VulnerabilityTemplate, VulnerabilityAssessment,
    VulnerabilityHistory, VulnerabilityAttachment, VulnerabilityStatus
)
from .serializers import (
    VulnerabilityListSerializer, VulnerabilityDetailSerializer,
    VulnerabilityCreateSerializer, VulnerabilityUpdateSerializer,
    VulnerabilityTemplateSerializer, VulnerabilityAssessmentSerializer,
    VulnerabilityHistorySerializer, VulnerabilityAttachmentSerializer,
    VulnerabilityBulkActionSerializer, VulnerabilityStatsSerializer,
    VulnerabilityTrendSerializer
)
from .filters import VulnerabilityFilter
from .tasks import (
    update_vulnerability_risk_scores, notify_vulnerability_assignment,
    scan_vulnerability_remediation
)


class VulnerabilityViewSet(viewsets.ModelViewSet):
    """
    ViewSet for vulnerability management
    
    Provides CRUD operations plus additional actions for vulnerability lifecycle
    """
    queryset = Vulnerability.objects.select_related('asset', 'assigned_to', 'created_by')
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = VulnerabilityFilter
    search_fields = ['title', 'description', 'cve_id', 'asset__name']
    ordering_fields = ['risk_score', 'cvss_v3_score', 'created_at', 'due_date', 'severity']
    ordering = ['-risk_score', '-created_at']
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'list':
            return VulnerabilityListSerializer
        elif self.action == 'create':
            return VulnerabilityCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return VulnerabilityUpdateSerializer
        return VulnerabilityDetailSerializer
    
    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = super().get_queryset()
        
        # Filter by asset permissions if user doesn't have global access
        if not self.request.user.has_perm('vulnerabilities.view_all_vulnerabilities'):
            # Implement asset-based filtering here
            pass
        
        return queryset
    
    def perform_create(self, serializer):
        """Set created_by when creating vulnerability"""
        serializer.save(created_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def assign(self, request, pk=None):
        """Assign vulnerability to user or group"""
        vulnerability = self.get_object()
        assigned_to_id = request.data.get('assigned_to')
        assignee_group = request.data.get('assignee_group')
        
        if assigned_to_id:
            try:
                assigned_to = User.objects.get(id=assigned_to_id)
                vulnerability.assigned_to = assigned_to
            except User.DoesNotExist:
                return Response(
                    {'error': 'User not found'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if assignee_group:
            vulnerability.assignee_group = assignee_group
        
        vulnerability.save()
        
        # Trigger notification task
        notify_vulnerability_assignment.delay(vulnerability.id, request.user.id)
        
        return Response({
            'message': 'Vulnerability assigned successfully',
            'assigned_to': vulnerability.assigned_to.get_full_name() if vulnerability.assigned_to else None,
            'assignee_group': vulnerability.assignee_group
        })
    
    @action(detail=True, methods=['post'])
    def close(self, request, pk=None):
        """Close vulnerability with reason"""
        vulnerability = self.get_object()
        reason = request.data.get('reason', '')
        resolution_method = request.data.get('resolution_method', 'fixed')
        
        vulnerability.status = VulnerabilityStatus.RESOLVED
        vulnerability.resolved_at = timezone.now()
        
        # Add to metadata
        if 'resolution' not in vulnerability.metadata:
            vulnerability.metadata['resolution'] = {}
        vulnerability.metadata['resolution'].update({
            'method': resolution_method,
            'reason': reason,
            'resolved_by': request.user.id,
            'resolved_at': timezone.now().isoformat()
        })
        
        vulnerability.save()
        
        # Create history entry
        VulnerabilityHistory.objects.create(
            vulnerability=vulnerability,
            field_name='status',
            old_value='open',
            new_value='resolved',
            change_reason=f"Closed: {reason}",
            changed_by=request.user
        )
        
        return Response({'message': 'Vulnerability closed successfully'})
    
    @action(detail=True, methods=['post'])
    def reopen(self, request, pk=None):
        """Reopen closed vulnerability"""
        vulnerability = self.get_object()
        reason = request.data.get('reason', '')
        
        vulnerability.status = VulnerabilityStatus.OPEN
        vulnerability.resolved_at = None
        vulnerability.save()
        
        # Create history entry
        VulnerabilityHistory.objects.create(
            vulnerability=vulnerability,
            field_name='status',
            old_value='resolved',
            new_value='open',
            change_reason=f"Reopened: {reason}",
            changed_by=request.user
        )
        
        return Response({'message': 'Vulnerability reopened successfully'})
    
    @action(detail=True, methods=['post'])
    def add_tag(self, request, pk=None):
        """Add tag to vulnerability"""
        vulnerability = self.get_object()
        tag = request.data.get('tag')
        
        if not tag:
            return Response(
                {'error': 'Tag is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        vulnerability.add_tag(tag)
        return Response({
            'message': f'Tag "{tag}" added successfully',
            'tags': vulnerability.tags
        })
    
    @action(detail=True, methods=['post'])
    def remove_tag(self, request, pk=None):
        """Remove tag from vulnerability"""
        vulnerability = self.get_object()
        tag = request.data.get('tag')
        
        if not tag:
            return Response(
                {'error': 'Tag is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        vulnerability.remove_tag(tag)
        return Response({
            'message': f'Tag "{tag}" removed successfully',
            'tags': vulnerability.tags
        })
    
    @action(detail=True, methods=['get'])
    def history(self, request, pk=None):
        """Get vulnerability change history"""
        vulnerability = self.get_object()
        history = VulnerabilityHistory.objects.filter(
            vulnerability=vulnerability
        ).order_by('-changed_at')
        
        serializer = VulnerabilityHistorySerializer(history, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def attachments(self, request, pk=None):
        """Get vulnerability attachments"""
        vulnerability = self.get_object()
        attachments = VulnerabilityAttachment.objects.filter(
            vulnerability=vulnerability
        ).order_by('-uploaded_at')
        
        serializer = VulnerabilityAttachmentSerializer(attachments, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def bulk_action(self, request):
        """Perform bulk actions on vulnerabilities"""
        serializer = VulnerabilityBulkActionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        vulnerability_ids = data['vulnerability_ids']
        action_type = data['action']
        
        # Get vulnerabilities
        vulnerabilities = Vulnerability.objects.filter(id__in=vulnerability_ids)
        if not vulnerabilities.exists():
            return Response(
                {'error': 'No vulnerabilities found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        updated_count = 0
        
        # Perform action
        if action_type == 'assign':
            assigned_to = None
            if data.get('assigned_to'):
                try:
                    assigned_to = User.objects.get(id=data['assigned_to'])
                except User.DoesNotExist:
                    return Response(
                        {'error': 'User not found'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            for vuln in vulnerabilities:
                vuln.assigned_to = assigned_to
                vuln.assignee_group = data.get('assignee_group', '')
                vuln.save()
                updated_count += 1
        
        elif action_type == 'close':
            for vuln in vulnerabilities:
                vuln.status = VulnerabilityStatus.RESOLVED
                vuln.resolved_at = timezone.now()
                vuln.save()
                updated_count += 1
        
        elif action_type == 'tag':
            tag = data['tag']
            for vuln in vulnerabilities:
                vuln.add_tag(tag)
                updated_count += 1
        
        elif action_type == 'priority':
            priority = data['priority']
            for vuln in vulnerabilities:
                vuln.priority = priority
                vuln.save()
                updated_count += 1
        
        return Response({
            'message': f'Bulk action completed on {updated_count} vulnerabilities',
            'updated_count': updated_count
        })
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get vulnerability statistics"""
        queryset = self.filter_queryset(self.get_queryset())
        
        # Basic counts
        stats = {
            'total_vulnerabilities': queryset.count(),
            'critical_count': queryset.filter(severity='critical').count(),
            'high_count': queryset.filter(severity='high').count(),
            'medium_count': queryset.filter(severity='medium').count(),
            'low_count': queryset.filter(severity='low').count(),
            'info_count': queryset.filter(severity='info').count(),
            
            'open_count': queryset.filter(status='open').count(),
            'in_progress_count': queryset.filter(status='in_progress').count(),
            'resolved_count': queryset.filter(status='resolved').count(),
        }
        
        # Due date statistics
        now = timezone.now()
        today_end = now.replace(hour=23, minute=59, second=59)
        week_end = now + timedelta(weeks=1)
        
        stats.update({
            'overdue_count': queryset.filter(
                due_date__lt=now,
                status='open'
            ).count(),
            'due_today_count': queryset.filter(
                due_date__date=now.date(),
                status='open'
            ).count(),
            'due_this_week_count': queryset.filter(
                due_date__lte=week_end,
                due_date__gte=now,
                status='open'
            ).count(),
        })
        
        # Averages
        aggregations = queryset.aggregate(
            avg_risk_score=Avg('risk_score'),
            avg_resolution_time_days=Avg(
                Case(
                    When(
                        resolved_at__isnull=False,
                        then=F('resolved_at') - F('first_discovered')
                    ),
                    output_field=IntegerField()
                )
            )
        )
        
        stats['avg_risk_score'] = round(aggregations['avg_risk_score'] or 0, 2)
        stats['avg_resolution_time_days'] = round(
            (aggregations['avg_resolution_time_days'].days if aggregations['avg_resolution_time_days'] else 0), 
            1
        )
        
        serializer = VulnerabilityStatsSerializer(stats)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def trends(self, request):
        """Get vulnerability trends over time"""
        days = int(request.query_params.get('days', 30))
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days)
        
        # Generate daily trend data
        trends = []
        current_date = start_date
        
        while current_date <= end_date:
            day_start = timezone.make_aware(datetime.combine(current_date, datetime.min.time()))
            day_end = timezone.make_aware(datetime.combine(current_date, datetime.max.time()))
            
            discovered_count = Vulnerability.objects.filter(
                first_discovered__range=(day_start, day_end)
            ).count()
            
            resolved_count = Vulnerability.objects.filter(
                resolved_at__range=(day_start, day_end)
            ).count()
            
            total_open = Vulnerability.objects.filter(
                first_discovered__lte=day_end,
                status='open'
            ).count()
            
            avg_risk = Vulnerability.objects.filter(
                first_discovered__lte=day_end,
                status='open'
            ).aggregate(avg_risk=Avg('risk_score'))['avg_risk'] or 0
            
            trends.append({
                'date': current_date,
                'discovered_count': discovered_count,
                'resolved_count': resolved_count,
                'total_open': total_open,
                'avg_risk_score': round(avg_risk, 2)
            })
            
            current_date += timedelta(days=1)
        
        serializer = VulnerabilityTrendSerializer(trends, many=True)
        return Response(serializer.data)


class VulnerabilityTemplateViewSet(viewsets.ModelViewSet):
    """ViewSet for vulnerability templates"""
    queryset = VulnerabilityTemplate.objects.all()
    serializer_class = VulnerabilityTemplateSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'cve_id', 'category']
    ordering_fields = ['title', 'severity', 'created_at']
    ordering = ['title']


class VulnerabilityAssessmentViewSet(viewsets.ModelViewSet):
    """ViewSet for vulnerability risk assessments"""
    queryset = VulnerabilityAssessment.objects.select_related('vulnerability')
    serializer_class = VulnerabilityAssessmentSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['vulnerability', 'exploit_available', 'in_wild_exploitation']
