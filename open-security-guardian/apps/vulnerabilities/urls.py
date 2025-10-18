"""
Vulnerability Management URLs

URL configuration for vulnerability-related API endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create router and register viewsets
# Note: Using empty prefix ('') because the parent url (guardian/urls.py) 
# already includes 'api/v1/vulnerabilities/', avoiding double nesting
router = DefaultRouter()
router.register(r'', views.VulnerabilityViewSet, basename='vulnerability')
router.register(r'templates', views.VulnerabilityTemplateViewSet, basename='vulnerability-template')
router.register(r'assessments', views.VulnerabilityAssessmentViewSet, basename='vulnerability-assessment')

app_name = 'vulnerabilities'

urlpatterns = [
    # Include router URLs directly
    path('', include(router.urls)),
    
    # Additional custom endpoints can be added here
    # path('export/', views.ExportVulnerabilitiesView.as_view(), name='export-vulnerabilities'),
    # path('import/', views.ImportVulnerabilitiesView.as_view(), name='import-vulnerabilities'),
]
