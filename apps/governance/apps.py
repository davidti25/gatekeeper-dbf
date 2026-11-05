from django.apps import AppConfig


class GovernanceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.governance"
    verbose_name = "Governança de Acessos & Identidades"

    def ready(self):
        import apps.governance.checks  # noqa: F401
        import apps.governance.signals  # noqa: F401
