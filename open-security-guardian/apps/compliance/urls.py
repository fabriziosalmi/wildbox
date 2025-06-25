from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ComplianceFrameworkViewSet, ComplianceControlViewSet, ComplianceAssessmentViewSet,
    ComplianceEvidenceViewSet, ComplianceResultViewSet, ComplianceExceptionViewSet,
    ComplianceMetricsViewSet
)

router = DefaultRouter()
router.register(r'frameworks', ComplianceFrameworkViewSet)
router.register(r'controls', ComplianceControlViewSet)
router.register(r'assessments', ComplianceAssessmentViewSet)
router.register(r'evidence', ComplianceEvidenceViewSet)
router.register(r'results', ComplianceResultViewSet)
router.register(r'exceptions', ComplianceExceptionViewSet)
router.register(r'metrics', ComplianceMetricsViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
