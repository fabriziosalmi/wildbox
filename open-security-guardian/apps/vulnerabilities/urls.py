"""
Vulnerability Management URLs

URL configuration for vulnerability-related API endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create router and register viewsets
router = DefaultRouter()
router.register(r'vulnerabilities', views.VulnerabilityViewSet, basename='vulnerability')
router.register(r'vulnerability-templates', views.VulnerabilityTemplateViewSet, basename='vulnerability-template')
router.register(r'vulnerability-assessments', views.VulnerabilityAssessmentViewSet, basename='vulnerability-assessment')

app_name = 'vulnerabilities'

urlpatterns = [
    # Include router URLs
    path('api/', include(router.urls)),
    
    # Additional custom endpoints can be added here
    # path('api/vulnerabilities/export/', views.ExportVulnerabilitiesView.as_view(), name='export-vulnerabilities'),
    # path('api/vulnerabilities/import/', views.ImportVulnerabilitiesView.as_view(), name='import-vulnerabilities'),
]
