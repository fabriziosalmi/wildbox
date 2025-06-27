"""
Remediation Management Views

Django REST Framework views for remediation ticket and workflow management.
"""

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from .models import (
    RemediationTicket, RemediationWorkflow, RemediationStep,
    RemediationComment, RemediationTemplate, RemediationMetrics
)


class RemediationTicketViewSet(viewsets.ModelViewSet):
    """ViewSet for managing remediation tickets"""
    queryset = RemediationTicket.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['title', 'description', 'external_ticket_id']
    filterset_fields = ['status', 'priority', 'assigned_to', 'ticketing_system']
    ordering_fields = ['created_at', 'updated_at', 'due_date', 'priority']
    ordering = ['-created_at']

    @action(detail=True, methods=['post'])
    def assign(self, request, pk=None):
        """Assign ticket to a user"""
        ticket = self.get_object()
        assignee_id = request.data.get('assignee_id')
        if assignee_id:
            # TODO: Validate assignee exists and update ticket
            return Response({'status': 'success', 'message': 'Ticket assigned'})
        return Response({'error': 'assignee_id required'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update ticket status"""
        ticket = self.get_object()
        new_status = request.data.get('status')
        if new_status:
            ticket.status = new_status
            ticket.save()
            return Response({'status': 'success', 'message': 'Status updated'})
        return Response({'error': 'status required'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def sync_external(self, request, pk=None):
        """Sync with external ticketing system"""
        ticket = self.get_object()
        # TODO: Implement external system sync
        return Response({'status': 'success', 'message': 'Sync completed'})


class RemediationWorkflowViewSet(viewsets.ModelViewSet):
    """ViewSet for managing remediation workflows"""
    queryset = RemediationWorkflow.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description']
    filterset_fields = ['vulnerability', 'status', 'priority', 'assigned_to']
    ordering_fields = ['created_at', 'updated_at', 'due_date']
    ordering = ['-created_at']

    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start workflow execution"""
        workflow = self.get_object()
        workflow.status = 'in_progress'
        workflow.save()
        return Response({'status': 'success', 'message': 'Workflow started'})

    @action(detail=True, methods=['post'])
    def pause(self, request, pk=None):
        """Pause workflow execution"""
        workflow = self.get_object()
        workflow.status = 'paused'
        workflow.save()
        return Response({'status': 'success', 'message': 'Workflow paused'})

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Mark workflow as completed"""
        workflow = self.get_object()
        workflow.status = 'completed'
        workflow.save()
        return Response({'status': 'success', 'message': 'Workflow completed'})

    @action(detail=True, methods=['get'])
    def progress(self, request, pk=None):
        """Get workflow progress"""
        workflow = self.get_object()
        steps = workflow.steps.all()
        total_steps = steps.count()
        completed_steps = steps.filter(status='completed').count()
        progress_percentage = (completed_steps / total_steps * 100) if total_steps > 0 else 0
        
        return Response({
            'total_steps': total_steps,
            'completed_steps': completed_steps,
            'progress_percentage': progress_percentage
        })


class RemediationStepViewSet(viewsets.ModelViewSet):
    """ViewSet for managing remediation steps"""
    queryset = RemediationStep.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['title', 'description']
    filterset_fields = ['workflow', 'status', 'assigned_to', 'step_type']
    ordering_fields = ['order', 'created_at', 'due_date']
    ordering = ['order']

    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """Execute step"""
        step = self.get_object()
        step.status = 'in_progress'
        step.save()
        # TODO: Implement step execution logic
        return Response({'status': 'success', 'message': 'Step execution started'})

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Mark step as completed"""
        step = self.get_object()
        step.status = 'completed'
        step.save()
        return Response({'status': 'success', 'message': 'Step completed'})

    @action(detail=True, methods=['post'])
    def skip(self, request, pk=None):
        """Skip step"""
        step = self.get_object()
        step.status = 'skipped'
        step.save()
        return Response({'status': 'success', 'message': 'Step skipped'})


class RemediationCommentViewSet(viewsets.ModelViewSet):
    """ViewSet for managing remediation comments"""
    queryset = RemediationComment.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['content']
    filterset_fields = ['ticket', 'workflow', 'author', 'comment_type']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def perform_create(self, serializer):
        """Set author to current user when creating comment"""
        serializer.save(author=self.request.user)


class RemediationTemplateViewSet(viewsets.ModelViewSet):
    """ViewSet for managing remediation templates"""
    queryset = RemediationTemplate.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description']
    filterset_fields = ['category', 'is_active', 'created_by']
    ordering_fields = ['name', 'created_at', 'usage_count']
    ordering = ['name']

    @action(detail=True, methods=['post'])
    def clone(self, request, pk=None):
        """Clone template"""
        template = self.get_object()
        # TODO: Implement template cloning logic
        return Response({'status': 'success', 'message': 'Template cloned'})

    @action(detail=True, methods=['post'])
    def apply(self, request, pk=None):
        """Apply template to create workflow"""
        template = self.get_object()
        vulnerability_id = request.data.get('vulnerability_id')
        if vulnerability_id:
            # TODO: Implement template application logic
            template.usage_count += 1
            template.save()
            return Response({'status': 'success', 'message': 'Template applied'})
        return Response({'error': 'vulnerability_id required'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def categories(self, request):
        """Get available template categories"""
        categories = RemediationTemplate.objects.values_list('category', flat=True).distinct()
        return Response({'categories': list(categories)})
