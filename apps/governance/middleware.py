"""
Middlewares de Segurança e Controle de Acesso para o GateKeeper-DBF.
"""

import logging

from allauth.mfa.models import Authenticator
from django.shortcuts import redirect

logger = logging.getLogger("gatekeeper.audit")

GRUPOS_COM_ESCRITA = {"Analista TI", "Gestor SecOps"}
CAMINHOS_LIVRES = (
    "/accounts/",
    "/login/",
    "/logout/",
    "/static/",
    "/media/",
)


class RequireMFAMiddleware:
    """
    Exige autenticação multifator (TOTP) para contas administrativas ou com privilégio de escrita.
    Contas que possuam is_staff ou pertençam aos grupos 'Analista TI' ou 'Gestor SecOps'
    são forçadas a cadastrar um autenticador TOTP antes de acessar as funcionalidades do sistema (CIS Safeguard 6.5).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if (
            user.is_authenticated
            and not request.path.startswith(CAMINHOS_LIVRES)
            and (user.is_staff or user.groups.filter(name__in=GRUPOS_COM_ESCRITA).exists())
            and not Authenticator.objects.filter(user=user, type=Authenticator.Type.TOTP).exists()
        ):
            return redirect("mfa_activate_totp")

        return self.get_response(request)
