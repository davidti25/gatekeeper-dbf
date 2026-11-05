"""
Sinais e Trilha de Auditoria SOC para o GateKeeper-DBF.

Captura eventos críticos de autenticação e identidade para ingestão em SIEM:
- Login com sucesso (NIST SP 800-61 / CIS 5.5)
- Falha de login / Brute Force (MITRE ATT&CK T1110)
- Logout / Encerramento de sessão
"""

import logging
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

logger = logging.getLogger('gatekeeper.audit')


def _get_client_ip(request):
    if not request:
        return 'UNKNOWN'
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'UNKNOWN')


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ip = _get_client_ip(request)
    logger.info(f"AUTH_LOGIN_SUCCESS: usuario='{user.username}' ip='{ip}'")


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    username = user.username if user else 'ANONIMO'
    ip = _get_client_ip(request)
    logger.info(f"AUTH_LOGOUT: usuario='{username}' ip='{ip}'")


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    ip = _get_client_ip(request)
    username = credentials.get('username', 'DESCONHECIDO') if credentials else 'DESCONHECIDO'
    logger.warning(f"AUTH_LOGIN_FAILED [MITRE T1110]: tentativa_usuario='{username}' ip='{ip}'")

