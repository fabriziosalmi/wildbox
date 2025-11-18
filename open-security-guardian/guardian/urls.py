"""
URL configuration for Open Security Guardian

The Guardian: Proactive Vulnerability Management
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from apps.core.views import HealthCheckView, MetricsView

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # Health check endpoint
    path('health/', HealthCheckView.as_view(), name='health'),
    
    # Metrics endpoint (Prometheus)
    path('metrics/', MetricsView.as_view(), name='metrics'),
    
    # API endpoints
    path('api/v1/assets/', include('apps.assets.urls')),
    path('api/v1/vulnerabilities/', include('apps.vulnerabilities.urls')),
    path('api/v1/scanners/', include('apps.scanners.urls')),
    path('api/v1/remediation/', include('apps.remediation.urls')),
    path('api/v1/compliance/', include('apps.compliance.urls')),
    path('api/v1/integrations/', include('apps.integrations.urls')),
    path('api/v1/reports/', include('apps.reporting.urls')),
]

# Serve media files and API docs in development
if settings.DEBUG:
    urlpatterns += [
        # API documentation
        path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
        path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
        path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    ]
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    
    # Debug toolbar
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns

# Custom admin site headers
admin.site.site_header = "Open Security Guardian"
admin.site.site_title = "Guardian Admin"
admin.site.index_title = "Vulnerability Management Administration"
