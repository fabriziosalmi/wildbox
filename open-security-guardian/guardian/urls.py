"""
URL configuration for Open Security Guardian

The Guardian: Proactive Vulnerability Management
"""

from django.urls import path, include
from django.conf import settings
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from apps.core.internal_views import RevokeTeamMembershipsView
from apps.core.views import HealthCheckView, MetricsView, TaskStatusView

urlpatterns = [
    # There is no admin/ route. Django's admin site was mounted here with no
    # model of guardian registered in it, so it managed nothing, and in the
    # image it answered 500: its pages need the static files' manifest, which
    # the image does not build (#665). The gateway never routed to it.

    # Health check endpoint
    path('health/', HealthCheckView.as_view(), name='health'),

    # Called by identity on the internal network when a member leaves a team
    # (#676). Outside /api/: not reachable through the gateway, and it
    # authenticates the caller itself (apps/core/internal_views.py).
    path(
        'internal/team-memberships/revoke/',
        RevokeTeamMembershipsView.as_view(),
        name='revoke-team-memberships',
    ),

    # Metrics endpoint (Prometheus)
    path('metrics/', MetricsView.as_view(), name='metrics'),
    
    # API endpoints
    # State of a dispatched Celery task, by the task_id an endpoint returned.
    path('api/v1/tasks/<uuid:task_id>/', TaskStatusView.as_view(), name='task-status'),
    path('api/v1/assets/', include('apps.assets.urls')),
    path('api/v1/vulnerabilities/', include('apps.vulnerabilities.urls')),
    path('api/v1/scanners/', include('apps.scanners.urls')),
    path('api/v1/remediation/', include('apps.remediation.urls')),
    path('api/v1/compliance/', include('apps.compliance.urls')),
    path('api/v1/integrations/', include('apps.integrations.urls')),
    path('api/v1/reports/', include('apps.reporting.urls')),
]

# Serve the API docs in development. Media files (generated reports,
# attachments) are not served as static files, even in development: they
# are outside /api/, so no gateway authentication and no team check applied
# to them. A team downloads its reports through the reports API (#642).
if settings.DEBUG:
    urlpatterns += [
        # API documentation
        path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
        path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
        path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    ]
    
    # Debug toolbar
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns
