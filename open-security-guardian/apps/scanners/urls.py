"""
Scanner Management URLs

URL configuration for scanner-related API endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create router and register viewsets
router = DefaultRouter()
router.register(r'scanners', views.ScannerViewSet, basename='scanner')
router.register(r'scan-profiles', views.ScanProfileViewSet, basename='scan-profile')
router.register(r'scans', views.ScanViewSet, basename='scan')
router.register(r'scan-results', views.ScanResultViewSet, basename='scan-result')
router.register(r'scan-schedules', views.ScanScheduleViewSet, basename='scan-schedule')

app_name = 'scanners'

urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
    
    # Additional custom endpoints
    # path('api/scanners/import/', views.ImportScanResultsView.as_view(), name='import-scan-results'),
    # path('api/scanners/export/', views.ExportScannersView.as_view(), name='export-scanners'),
]
