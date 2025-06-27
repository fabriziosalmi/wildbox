"""
Integrations URLs

URL configuration for external system integration endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create router and register viewsets
router = DefaultRouter()
router.register(r'systems', views.ExternalSystemViewSet, basename='external-system')
router.register(r'mappings', views.IntegrationMappingViewSet, basename='integration-mapping')
router.register(r'sync-records', views.SyncRecordViewSet, basename='sync-record')
router.register(r'webhooks', views.WebhookEndpointViewSet, basename='webhook-endpoint')
router.register(r'logs', views.IntegrationLogViewSet, basename='integration-log')
router.register(r'notifications', views.NotificationChannelViewSet, basename='notification-channel')

app_name = 'integrations'

urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
    
    # Additional custom endpoints
    # path('api/integrations/test-connection/', views.TestConnectionView.as_view(), name='test-connection'),
    # path('api/integrations/sync-now/', views.TriggerSyncView.as_view(), name='trigger-sync'),
    # path('webhook/<uuid:webhook_id>/', views.WebhookReceiverView.as_view(), name='webhook-receiver'),
]
