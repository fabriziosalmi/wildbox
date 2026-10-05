"""
Remediation Management Views

Django REST Framework views for remediation ticket and workflow management.

Everything here is bookkeeping in guardian's own database: tickets mirror
tickets of an external system that guardian does not talk to (the
``sync_external`` action that answered "Sync completed" was removed, #644),
and workflows and steps are worked by people. An action answers success
only for something it stored.
"""

import copy

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework import viewsets, status
from apps.core.permissions import IsGatewayAdminOrReadOnly
from apps.core.tenancy import TeamScopedViewSetMixin
from apps.vulnerabilities.models import Vulnerability
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from .models import (
    RemediationTicket, RemediationWorkflow, RemediationStep,
    RemediationComment, RemediationStatus, RemediationTemplate,
)
from .serializers import (
    RemediationCommentSerializer, RemediationStepSerializer,
    RemediationTemplateSerializer, RemediationTicketSerializer,
    RemediationWorkflowSerializer,
)


def _template_steps_error(steps):
    """Why a template's ``step_templates`` cannot become steps, or None.

    ``step_templates`` is free-form JSON. ``RemediationTemplate.
    apply_to_workflow`` reads each entry as an object and copies its values
    into a RemediationStep, so anything else would fail half-way through
    (or, for a title too long, only on PostgreSQL).
    """
    if not isinstance(steps, list):
        return 'step_templates must be a list.'
    title_length = RemediationStep._meta.get_field('title').max_length
    texts = (
        'title', 'description', 'instructions', 'validation_criteria',
        'automation_script',
    )
    for number, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            return f'Step {number} must be an object.'
        for key in texts:
            if key in step and not isinstance(step[key], str):
                return f'Step {number}: {key} must be a string.'
        if len(step.get('title', '')) > title_length:
            return f'Step {number}: title is longer than {title_length} characters.'
        minutes = step.get('estimated_duration_minutes')
        if minutes is not None and (
            isinstance(minutes, bool) or not isinstance(minutes, int) or minutes < 0
        ):
            return (
                f'Step {number}: estimated_duration_minutes must be a whole '
                'number of minutes, 0 or more.'
            )
    return None


class RemediationTicketViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing remediation tickets"""
    queryset = RemediationTicket.objects.all()
    serializer_class = RemediationTicketSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['title', 'description', 'external_ticket_id']
    filterset_fields = ['status', 'priority', 'assigned_to', 'system']
    ordering_fields = ['created_at', 'updated_at', 'due_date', 'priority']
    ordering = ['-created_at']

    def perform_create(self, serializer):
        """Record the gateway-authenticated user as the creator."""
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def assign(self, request, pk=None):
        """Assign the ticket to a member of the caller's team.

        This answered "Ticket assigned" for any ``assignee_id``, a user
        that does not exist included, and left the ticket as it was (#644).
        """
        ticket = self.get_object()
        assignee_id = request.data.get('assignee_id')
        if assignee_id in (None, ''):
            return Response({'error': 'assignee_id required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if isinstance(assignee_id, bool):  # True would be user 1
                raise ValueError(assignee_id)
            # A current member of the caller's team only (#642).
            assignee = self.team_queryset(User).get(pk=assignee_id)
        except (User.DoesNotExist, ValueError, TypeError):
            return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
        ticket.assigned_to = assignee
        ticket.save()
        return Response({
            'status': 'success',
            'message': 'Ticket assigned',
            'assigned_to': assignee.pk,
        })

    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update ticket status"""
        ticket = self.get_object()
        new_status = request.data.get('status')
        if not new_status:
            return Response({'error': 'status required'}, status=status.HTTP_400_BAD_REQUEST)
        # Any string was stored, one the model does not define included.
        if new_status not in RemediationStatus.values:
            return Response(
                {'error': 'Unknown status', 'valid': RemediationStatus.values},
                status=status.HTTP_400_BAD_REQUEST,
            )
        ticket.status = new_status
        ticket.save()
        return Response({'status': 'success', 'message': 'Status updated'})


class RemediationWorkflowViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing remediation workflows"""
    queryset = RemediationWorkflow.objects.all()
    serializer_class = RemediationWorkflowSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['title', 'description']
    filterset_fields = ['vulnerability', 'status', 'priority', 'assigned_to']
    ordering_fields = ['created_at', 'updated_at', 'planned_completion_date']
    ordering = ['-created_at']

    def perform_create(self, serializer):
        """Record the gateway-authenticated user as the creator."""
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start workflow execution"""
        workflow = self.get_object()
        workflow.status = RemediationStatus.IN_PROGRESS
        # The dates are what duration_days and calculate_sla_status read;
        # setting the status alone left a started workflow without a start
        # and a completed one without an end (#644).
        if workflow.actual_start_date is None:
            workflow.actual_start_date = timezone.now()
        workflow.actual_completion_date = None
        workflow.save()
        return Response({'status': 'success', 'message': 'Workflow started'})

    # There is no ``pause`` action: it stored the status "paused", which
    # RemediationStatus does not define, so the API then refused that
    # workflow's own status on a PUT and as a filter (#644). A workflow is
    # put on hold with PATCH {"status": "deferred"}.

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Mark workflow as completed"""
        workflow = self.get_object()
        workflow.status = RemediationStatus.COMPLETED
        workflow.actual_completion_date = timezone.now()
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


class RemediationStepViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing remediation steps"""
    queryset = RemediationStep.objects.all()
    serializer_class = RemediationStepSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['title', 'description']
    filterset_fields = ['workflow', 'status', 'assigned_to']
    ordering_fields = ['order', 'created_at', 'completed_at']
    ordering = ['order']

    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """Execute step"""
        step = self.get_object()
        step.start_execution(request.user)
        return Response({'status': 'success', 'message': 'Step execution started'})

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        """Mark step as completed"""
        step = self.get_object()
        # complete_execution also records the duration and moves the
        # workflow's progress; setting the status alone left both stale.
        step.complete_execution(
            notes=request.data.get('notes'),
            validation_results=request.data.get('validation_results'),
        )
        return Response({'status': 'success', 'message': 'Step completed'})

    @action(detail=True, methods=['post'])
    def skip(self, request, pk=None):
        """Skip step"""
        step = self.get_object()
        step.status = 'skipped'
        step.save()
        return Response({'status': 'success', 'message': 'Step skipped'})


class RemediationCommentViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing remediation comments"""
    queryset = RemediationComment.objects.all()
    serializer_class = RemediationCommentSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['content']
    # A comment belongs to a workflow, not to a ticket: reach the ticket
    # through the workflow.
    filterset_fields = ['workflow', 'workflow__ticket', 'author', 'comment_type']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def perform_create(self, serializer):
        """Set author to current user when creating comment"""
        serializer.save(author=self.request.user)


class RemediationTemplateViewSet(TeamScopedViewSetMixin, viewsets.ModelViewSet):
    """ViewSet for managing remediation templates"""
    queryset = RemediationTemplate.objects.all()
    serializer_class = RemediationTemplateSerializer
    permission_classes = [IsGatewayAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['name', 'description']
    filterset_fields = ['category', 'is_active', 'created_by']
    ordering_fields = ['name', 'created_at', 'usage_count']
    ordering = ['name']

    def perform_create(self, serializer):
        """Record the gateway-authenticated user as the creator."""
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def clone(self, request, pk=None):
        """Store a copy of the template in the caller's team; answer it.

        This answered "Template cloned" and created nothing (#644). The
        copy takes ``name`` from the body, or the original's name followed
        by " (copy)"; it starts unused (``usage_count`` 0) and belongs to
        the caller.
        """
        template = self.get_object()
        name = request.data.get('name', f'{template.name} (copy)')
        max_length = RemediationTemplate._meta.get_field('name').max_length
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > max_length:
            return Response(
                {'name': [f'A name of 1 to {max_length} characters.']},
                status=status.HTTP_400_BAD_REQUEST,
            )
        duplicate = RemediationTemplate.objects.create(
            team_id=template.team_id,
            name=name.strip(),
            description=template.description,
            category=template.category,
            remediation_type=template.remediation_type,
            default_priority=template.default_priority,
            estimated_effort_hours=template.estimated_effort_hours,
            step_templates=copy.deepcopy(template.step_templates),
            rollback_template=template.rollback_template,
            testing_template=template.testing_template,
            vulnerability_types=copy.deepcopy(template.vulnerability_types),
            asset_types=copy.deepcopy(template.asset_types),
            is_active=template.is_active,
            created_by=request.user,
        )
        return Response(
            self.get_serializer(duplicate).data, status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['post'])
    def apply(self, request, pk=None):
        """Create a remediation workflow for a vulnerability from the template.

        This counted a use of the template, created no workflow and
        answered "Template applied" (#644). It now creates the workflow of
        the team's vulnerability ``vulnerability_id``, with the template's
        type, plans and steps (``RemediationTemplate.apply_to_workflow``),
        and answers it. A vulnerability has one workflow: a second one is
        refused with 409.
        """
        template = self.get_object()
        vulnerability_id = request.data.get('vulnerability_id')
        if not vulnerability_id:
            return Response({'error': 'vulnerability_id required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # One of the caller's team's vulnerabilities (#642).
            vulnerability = self.team_queryset(Vulnerability).get(pk=vulnerability_id)
        except (Vulnerability.DoesNotExist, ValidationError, ValueError, TypeError):
            return Response({'error': 'Vulnerability not found'}, status=status.HTTP_400_BAD_REQUEST)

        steps_error = _template_steps_error(template.step_templates)
        if steps_error:
            return Response(
                {'detail': steps_error, 'code': 'TEMPLATE_STEPS_INVALID'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        title = request.data.get('title')
        title_length = RemediationWorkflow._meta.get_field('title').max_length
        if title in (None, ''):
            title = f'{template.name}: {vulnerability.title}'[:title_length]
        elif not isinstance(title, str) or len(title) > title_length:
            return Response(
                {'title': [f'A title of 1 to {title_length} characters.']},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # All or nothing: no workflow without its steps, no use counted
            # for a workflow that was not created.
            with transaction.atomic():
                workflow = RemediationWorkflow.objects.create(
                    vulnerability=vulnerability,
                    title=title,
                    remediation_type=template.remediation_type,
                    priority=template.default_priority,
                    created_by=request.user,
                )
                template.apply_to_workflow(workflow)
        except IntegrityError:
            # The one-to-one key: the vulnerability has its workflow. The
            # database decides, so two requests at once cannot both pass.
            return Response(
                {
                    'detail': 'This vulnerability already has a remediation workflow.',
                    'code': 'WORKFLOW_EXISTS',
                },
                status=status.HTTP_409_CONFLICT,
            )
        return Response(
            RemediationWorkflowSerializer(
                workflow, context=self.get_serializer_context()
            ).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=False, methods=['get'])
    def categories(self, request):
        """Get available template categories"""
        # The caller's team's templates only (#642).
        categories = (
            self.get_queryset().order_by().values_list('category', flat=True).distinct()
        )
        return Response({'categories': list(categories)})
