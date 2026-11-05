"""
Checagens de Integridade e Segurança do Sistema (Django System Checks - Fase 10.6).

Registradas como deploy checks (@register(Tags.security, deploy=True)) para validação
em 'python manage.py check --deploy' e no pipeline DevSecOps CI/CD.
"""

from django.conf import settings
from django.core.checks import Error, Tags, register


@register(Tags.security, deploy=True)
def check_mfa_totp_tolerance(app_configs, **kwargs):
    """
    gatekeeper.E001: Valida que a tolerância de tempo do TOTP não é maior que 0 em produção.
    Tolerância > 0 cria uma janela de reuso temporal indevida de códigos TOTP.
    """
    errors = []
    if not settings.DEBUG and getattr(settings, "MFA_TOTP_TOLERANCE", 0) > 0:
        errors.append(
            Error(
                "MFA_TOTP_TOLERANCE não pode ser maior que 0 em produção para evitar janelas de reuso de código TOTP.",
                hint="Defina MFA_TOTP_TOLERANCE=0 no ambiente de produção.",
                id="gatekeeper.E001",
            )
        )
    return errors


@register(Tags.security, deploy=True)
def check_shared_cache(app_configs, **kwargs):
    """
    gatekeeper.E002: Valida que o cache padrão é compartilhado entre workers em produção.
    LocMemCache ou DummyCache resultam em rate limits e invalidações de TOTP isoladas por processo.
    """
    errors = []
    if not settings.DEBUG:
        default_cache = settings.CACHES.get("default", {})
        backend = default_cache.get("BACKEND", "")
        if backend in (
            "django.core.cache.backends.locmem.LocMemCache",
            "django.core.cache.backends.dummy.DummyCache",
        ):
            errors.append(
                Error(
                    f"O cache padrão '{backend}' não é compartilhado entre workers em produção.",
                    hint="Configure CACHE_URL com DatabaseCache ('dbcache://') ou Redis ('redis://').",
                    id="gatekeeper.E002",
                )
            )
    return errors


@register(Tags.security, deploy=True)
def check_rate_limits_key(app_configs, **kwargs):
    """
    gatekeeper.E003: Valida que o rate limit de login contém limitação por conta ('key').
    Sem 'key', o allauth limita apenas por IP, permitindo ataques distribuídos de força bruta contra uma conta alvo.
    """
    errors = []
    if not settings.DEBUG:
        rate_limits = getattr(settings, "ACCOUNT_RATE_LIMITS", {})
        login_failed = rate_limits.get("login_failed", "")
        if "key" not in login_failed:
            errors.append(
                Error(
                    "O rate limit de 'login_failed' deve conter controle por conta ('key') para mitigar ataques distribuídos (MITRE T1110).",
                    hint="Configure ACCOUNT_RATE_LIMITS['login_failed'] = '10/m/ip,5/5m/key'.",
                    id="gatekeeper.E003",
                )
            )
    return errors


@register(Tags.security, deploy=True)
def check_totp_insecure_bypass(app_configs, **kwargs):
    """
    gatekeeper.E004: Valida que códigos de bypass inseguro de TOTP não estão presentes em produção.
    """
    errors = []
    if not settings.DEBUG and getattr(settings, "MFA_TOTP_INSECURE_BYPASS_CODE", None):
        errors.append(
            Error(
                "MFA_TOTP_INSECURE_BYPASS_CODE está definido em ambiente de produção (DEBUG=False).",
                hint="Remova MFA_TOTP_INSECURE_BYPASS_CODE das variáveis de ambiente de produção.",
                id="gatekeeper.E004",
            )
        )
    return errors


def run_gatekeeper_deploy_checks():
    """Executa todas as checagens customizadas de segurança do GateKeeper."""
    return (
        check_mfa_totp_tolerance(None)
        + check_shared_cache(None)
        + check_rate_limits_key(None)
        + check_totp_insecure_bypass(None)
    )
