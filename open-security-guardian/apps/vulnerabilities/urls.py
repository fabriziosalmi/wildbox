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
#
# Order matters: Django tries the patterns in registration order, and the
# vulnerability detail route on the empty prefix, ^(?P<pk>[^/.]+)/$, also
# matches "templates/" and "assessments/". Registered first, it served them
# as VulnerabilityViewSet.retrieve(pk="templates") -> 404, and the template
# and assessment viewsets were unreachable (#514). The named prefixes must
# come before the empty one.
router = DefaultRouter()
router.register(r'templates', views.VulnerabilityTemplateViewSet, basename='vulnerability-template')
router.register(r'assessments', views.VulnerabilityAssessmentViewSet, basename='vulnerability-assessment')
router.register(r'', views.VulnerabilityViewSet, basename='vulnerability')

app_name = 'vulnerabilities'

urlpatterns = [
    # Include router URLs directly
    path('', include(router.urls)),
    
    # Additional custom endpoints can be added here
    # path('export/', views.ExportVulnerabilitiesView.as_view(), name='export-vulnerabilities'),
    # path('import/', views.ImportVulnerabilitiesView.as_view(), name='import-vulnerabilities'),
]
