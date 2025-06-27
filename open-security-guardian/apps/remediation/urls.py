"""
Remediation Management URLs

URL configuration for remediation-related API endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create router and register viewsets
router = DefaultRouter()
router.register(r'tickets', views.RemediationTicketViewSet, basename='remediation-ticket')
router.register(r'workflows', views.RemediationWorkflowViewSet, basename='remediation-workflow')
router.register(r'steps', views.RemediationStepViewSet, basename='remediation-step')
router.register(r'comments', views.RemediationCommentViewSet, basename='remediation-comment')
router.register(r'templates', views.RemediationTemplateViewSet, basename='remediation-template')

app_name = 'remediation'

urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
    
    # Additional custom endpoints
    # path('api/remediation/metrics/', views.RemediationMetricsView.as_view(), name='remediation-metrics'),
    # path('api/remediation/export/', views.ExportRemediationView.as_view(), name='export-remediation'),
]
