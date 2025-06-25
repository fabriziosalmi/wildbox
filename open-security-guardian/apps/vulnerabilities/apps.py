from django.apps import AppConfig


class VulnerabilitiesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.vulnerabilities'
    verbose_name = 'Vulnerability Management'

    def ready(self):
        """Initialize signals when app is ready"""
        import apps.vulnerabilities.signals  # noqa
