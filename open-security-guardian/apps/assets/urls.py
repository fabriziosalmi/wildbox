"""
Asset Management URL Configuration
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    AssetViewSet, EnvironmentViewSet, BusinessFunctionViewSet,
    AssetGroupViewSet, AssetDiscoveryRuleViewSet, AssetSoftwareViewSet,
    AssetPortViewSet
)

router = DefaultRouter()
router.register(r'assets', AssetViewSet)
router.register(r'environments', EnvironmentViewSet)
router.register(r'business-functions', BusinessFunctionViewSet)
router.register(r'groups', AssetGroupViewSet)
router.register(r'discovery-rules', AssetDiscoveryRuleViewSet)
router.register(r'software', AssetSoftwareViewSet)
router.register(r'ports', AssetPortViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
