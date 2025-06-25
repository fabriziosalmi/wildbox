from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ReportTemplateViewSet, ReportScheduleViewSet, ReportViewSet,
    DashboardViewSet, WidgetViewSet, ReportMetricsViewSet, AlertRuleViewSet
)

router = DefaultRouter()
router.register(r'templates', ReportTemplateViewSet)
router.register(r'schedules', ReportScheduleViewSet)
router.register(r'reports', ReportViewSet)
router.register(r'dashboards', DashboardViewSet)
router.register(r'widgets', WidgetViewSet)
router.register(r'metrics', ReportMetricsViewSet)
router.register(r'alerts', AlertRuleViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
