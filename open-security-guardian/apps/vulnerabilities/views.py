"""
Vulnerability Management Views

DRF ViewSets and API views for vulnerability management.
"""

from django.shortcuts import get_object_or_404
from django.db.models import Q, Count, Avg, F, Case, When, IntegerField
from django.utils import timezone
from django.contrib.auth.models import User
from rest_framework import viewsets, status, filters
from apps.core.permissions import IsGatewayAdminOrReadOnly
from apps.core.tenancy import TeamScopedViewSetMixin
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from datetime import timedelta, datetime

from .models import (
    Vulnerability, VulnerabilityTemplate, VulnerabilityAssessment,
    VulnerabilityHistory, VulnerabilityStatus
)
from .serializers import (
    VulnerabilityListSerializer, VulnerabilityDetailSerializer,
    VulnerabilityCreateSerializer, VulnerabilityUpdateSerializer,
    VulnerabilityTemplateSerializer, VulnerabilityAssessmentSerializer,
    VulnerabilityHistorySerializer,
    VulnerabilityBulkActionSerializer, VulnerabilityStatsSerializer,
    VulnerabilityTrendSerializer
)
from .filters import VulnerabilityFilter
from .tasks import (
    update_vulnerability_risk_scores, notify_vulnerability_assignment,
)


class VulnerabilityViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """
    ViewSet for vulnerability management
    
    Provides CRUD operations plus additional actions for vulnerability lifecycle
    """
    queryset = Vulnerability.objects.select_related('asset', 'assigned_to', 'created_by')
    permission_classes = [IsGatewayAdminOrReadOnly]
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
            # Non-admin users can only see vulnerabilities assigned to them
            queryset = queryset.filter(
                Q(assigned_to=self.request.user) |
                Q(created_by=self.request.user)
            )

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

        # With neither, nothing was assigned and the answer still said
        # "assigned successfully" (#644).
        if not assigned_to_id and not assignee_group:
            return Response(
                {'error': "Either 'assigned_to' or 'assignee_group' is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if assigned_to_id:
            try:
                # A member of the caller's team only (#642).
                assigned_to = self.team_queryset(User).get(id=assigned_to_id)
                vulnerability.assigned_to = assigned_to
            except (User.DoesNotExist, ValueError, TypeError):
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
    
    def _close(self, vulnerability, reason='', resolution_method='fixed'):
        """Resolve one vulnerability; what ``close`` and a bulk close do."""
        user = self.request.user
        # The status it really had: the entry said "open" whatever it was.
        old_status = vulnerability.status
        vulnerability.status = VulnerabilityStatus.RESOLVED
        vulnerability.resolved_at = timezone.now()

        # Add to metadata
        if 'resolution' not in vulnerability.metadata:
            vulnerability.metadata['resolution'] = {}
        vulnerability.metadata['resolution'].update({
            'method': resolution_method,
            'reason': reason,
            'resolved_by': user.id,
            'resolved_at': timezone.now().isoformat()
        })

        vulnerability.save()

        # Create history entry
        VulnerabilityHistory.objects.create(
            vulnerability=vulnerability,
            field_name='status',
            old_value=old_status,
            new_value=VulnerabilityStatus.RESOLVED,
            change_reason=f"Closed: {reason}",
            changed_by=user
        )

    def _reopen(self, vulnerability, reason=''):
        """Reopen one vulnerability; what ``reopen`` and a bulk reopen do."""
        old_status = vulnerability.status
        vulnerability.status = VulnerabilityStatus.OPEN
        vulnerability.resolved_at = None
        vulnerability.save()

        # Create history entry
        VulnerabilityHistory.objects.create(
            vulnerability=vulnerability,
            field_name='status',
            old_value=old_status,
            new_value=VulnerabilityStatus.OPEN,
            change_reason=f"Reopened: {reason}",
            changed_by=self.request.user
        )

    @action(detail=True, methods=['post'])
    def close(self, request, pk=None):
        """Close vulnerability with reason"""
        vulnerability = self.get_object()
        self._close(
            vulnerability,
            reason=request.data.get('reason', ''),
            resolution_method=request.data.get('resolution_method', 'fixed'),
        )
        return Response({'message': 'Vulnerability closed successfully'})

    @action(detail=True, methods=['post'])
    def reopen(self, request, pk=None):
        """Reopen closed vulnerability"""
        vulnerability = self.get_object()
        self._reopen(vulnerability, reason=request.data.get('reason', ''))
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
        ).order_by('-timestamp')
        
        serializer = VulnerabilityHistorySerializer(history, many=True)
        return Response(serializer.data)
    
    # There is no ``attachments`` action. It listed VulnerabilityAttachment
    # rows, and guardian has never had a route, a task or a command that
    # creates one; each row's ``file`` would have been a /media/ URL that
    # nothing serves (#642 stopped serving media: it is outside /api/, so
    # neither the gateway's authentication nor the team check applied). The
    # route always answered an empty list, and was removed (#724).

    @action(detail=False, methods=['post'])
    def bulk_action(self, request):
        """Perform bulk actions on vulnerabilities"""
        serializer = VulnerabilityBulkActionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        vulnerability_ids = data['vulnerability_ids']
        action_type = data['action']
        
        # Get vulnerabilities: the caller's team's only (#642), and among
        # them those a member may see.
        vulnerabilities = self.get_queryset().filter(id__in=vulnerability_ids)
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
                    assigned_to = self.team_queryset(User).get(id=data['assigned_to'])
                except User.DoesNotExist:
                    return Response(
                        {'error': 'User not found'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Only what the request names, as the ``assign`` action does: a
            # group given alone unassigned every user, and a user given
            # alone cleared every group (#644).
            for vuln in vulnerabilities:
                if assigned_to is not None:
                    vuln.assigned_to = assigned_to
                if data.get('assignee_group'):
                    vuln.assignee_group = data['assignee_group']
                vuln.save()
                updated_count += 1

        elif action_type == 'close':
            for vuln in vulnerabilities:
                self._close(vuln, reason=data.get('reason', ''))
                updated_count += 1

        elif action_type == 'reopen':
            for vuln in vulnerabilities:
                self._reopen(vuln, reason=data.get('reason', ''))
                updated_count += 1

        elif action_type == 'tag':
            tag = data['tag']
            for vuln in vulnerabilities:
                vuln.add_tag(tag)
                updated_count += 1

        elif action_type == 'untag':
            tag = data['tag']
            for vuln in vulnerabilities:
                vuln.remove_tag(tag)
                updated_count += 1

        elif action_type == 'priority':
            priority = data['priority']
            for vuln in vulnerabilities:
                vuln.priority = priority
                vuln.save()
                updated_count += 1

        else:
            # An action the serializer accepts and nothing above performs:
            # "reopen" and "untag" were, and answered "Bulk action completed
            # on 0 vulnerabilities" (#644). Refuse instead of reporting
            # work that was not done.
            return Response(
                {'action': [f'"{action_type}" is not a supported bulk action.']},
                status=status.HTTP_400_BAD_REQUEST
            )

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
            avg_risk_score=Avg('risk_score')
        )
        
        stats['avg_risk_score'] = round(aggregations['avg_risk_score'] or 0, 2)
        
        # Calculate average resolution time in Python (more reliable than DB aggregation)
        # Only consider resolved vulnerabilities with valid timestamps
        resolved_vulns = queryset.filter(
            status='resolved',
            resolved_at__isnull=False,
            first_discovered__isnull=False
        ).values_list('resolved_at', 'first_discovered')
        
        if resolved_vulns:
            resolution_times = [
                (resolved - discovered).total_seconds() / 86400  # Convert to days
                for resolved, discovered in resolved_vulns
                if resolved and discovered and resolved > discovered  # Safety check
            ]
            stats['avg_resolution_time_days'] = round(
                sum(resolution_times) / len(resolution_times) if resolution_times else 0,
                1
            )
        else:
            stats['avg_resolution_time_days'] = 0
        
        serializer = VulnerabilityStatsSerializer(stats)
        return Response(serializer.data)
    
    #: The longest window ``trends`` computes: it runs four queries per day.
    MAX_TREND_DAYS = 366

    @action(detail=False, methods=['get'])
    def trends(self, request):
        """Get vulnerability trends over time"""
        # ?days=abc answered 500, and nothing bounded the window (#644).
        try:
            days = int(request.query_params.get('days', 30))
        except (TypeError, ValueError):
            days = -1
        if not 0 <= days <= self.MAX_TREND_DAYS:
            return Response(
                {'days': [f'A whole number of days from 0 to {self.MAX_TREND_DAYS}.']},
                status=status.HTTP_400_BAD_REQUEST
            )
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days)

        # Generate daily trend data from the rows the list would show: the
        # caller's team's findings (#642) and, for a member, those assigned
        # to or created by them (get_queryset).
        vulnerabilities = self.get_queryset()
        trends = []
        current_date = start_date
        
        while current_date <= end_date:
            day_start = timezone.make_aware(datetime.combine(current_date, datetime.min.time()))
            day_end = timezone.make_aware(datetime.combine(current_date, datetime.max.time()))
            
            discovered_count = vulnerabilities.filter(
                first_discovered__range=(day_start, day_end)
            ).count()
            
            resolved_count = vulnerabilities.filter(
                resolved_at__range=(day_start, day_end)
            ).count()
            
            total_open = vulnerabilities.filter(
                first_discovered__lte=day_end,
                status='open'
            ).count()
            
            avg_risk = vulnerabilities.filter(
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


class VulnerabilityTemplateViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for vulnerability templates"""
    queryset = VulnerabilityTemplate.objects.all()
    serializer_class = VulnerabilityTemplateSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'cve_id', 'category']
    ordering_fields = ['title', 'severity', 'created_at']
    ordering = ['title']


class VulnerabilityAssessmentViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for vulnerability risk assessments"""
    queryset = VulnerabilityAssessment.objects.select_related('vulnerability')
    serializer_class = VulnerabilityAssessmentSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['vulnerability', 'exploit_available', 'exploit_public']
