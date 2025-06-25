"""
Core Views - Health checks and system endpoints

The Guardian: Proactive Vulnerability Management
"""

import json
import psutil
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.conf import settings
from django.db import connection
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from apps.core.models import SystemConfiguration
import redis


class HealthCheckView(APIView):
    """Health check endpoint for monitoring."""
    
    authentication_classes = []
    permission_classes = []
    
    def get(self, request):
        """Return system health status."""
        health_data = {
            'status': 'healthy',
            'timestamp': timezone.now().isoformat(),
            'version': '1.0.0',
            'checks': {}
        }
        
        # Database check
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            health_data['checks']['database'] = {'status': 'healthy'}
        except Exception as e:
            health_data['checks']['database'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_data['status'] = 'unhealthy'
        
        # Redis check
        try:
            cache.set('health_check', 'ok', 10)
            cache.get('health_check')
            health_data['checks']['redis'] = {'status': 'healthy'}
        except Exception as e:
            health_data['checks']['redis'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_data['status'] = 'unhealthy'
        
        # System resources check
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            health_data['checks']['system'] = {
                'status': 'healthy',
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'cpu_percent': psutil.cpu_percent(interval=1)
            }
            
            # Alert if resources are high
            if memory.percent > 90 or disk.percent > 90:
                health_data['checks']['system']['status'] = 'warning'
                
        except Exception as e:
            health_data['checks']['system'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
        
        response_status = status.HTTP_200_OK if health_data['status'] == 'healthy' else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(health_data, status=response_status)


class MetricsView(View):
    """Prometheus metrics endpoint."""
    
    def get(self, request):
        """Return Prometheus metrics."""
        if not settings.PROMETHEUS_ENABLED:
            return HttpResponse("Metrics disabled", status=404)
        
        try:
            from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
            return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)
        except ImportError:
            return HttpResponse("Prometheus client not available", status=503)


class SystemInfoView(APIView):
    """System information endpoint."""
    
    def get(self, request):
        """Return system information."""
        system_info = {
            'application': {
                'name': 'Open Security Guardian',
                'version': '1.0.0',
                'description': 'Proactive Vulnerability Management Platform'
            },
            'system': {
                'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                'django_version': django.VERSION[:3],
                'platform': platform.platform(),
                'architecture': platform.architecture()[0],
            },
            'database': {
                'engine': settings.DATABASES['default']['ENGINE'].split('.')[-1],
                'name': settings.DATABASES['default']['NAME'],
            },
            'cache': {
                'backend': settings.CACHES['default']['BACKEND'].split('.')[-1],
            }
        }
        
        return Response(system_info)


# Import required modules for system info
import sys
import platform
import django
from django.utils import timezone
