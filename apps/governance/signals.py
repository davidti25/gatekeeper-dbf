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

from .utils import get_client_ip

logger = logging.getLogger("gatekeeper.audit")


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ip = get_client_ip(request)
    logger.info("AUTH_LOGIN_SUCCESS", extra={"audit": {"usuario": user.username, "ip": ip}})


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    username = user.username if user else "ANONIMO"
    ip = get_client_ip(request)
    logger.info("AUTH_LOGOUT", extra={"audit": {"usuario": username, "ip": ip}})


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    ip = get_client_ip(request)
    username = credentials.get("username", "DESCONHECIDO") if credentials else "DESCONHECIDO"
    logger.warning(
        "AUTH_LOGIN_FAILED [MITRE T1110]",
        extra={"audit": {"tentativa_usuario": username, "ip": ip}},
    )
