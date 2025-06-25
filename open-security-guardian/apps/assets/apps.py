from django.apps import AppConfig


class AssetsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.assets'
    verbose_name = 'Asset Management'

    def ready(self):
        """Initialize signals when app is ready"""
        import apps.assets.signals  # noqa
