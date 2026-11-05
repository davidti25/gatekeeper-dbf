"""
Middlewares de Segurança e Controle de Acesso para o GateKeeper-DBF.
"""

import logging

from allauth.mfa.models import Authenticator
from django.db import DatabaseError, connection
from django.http import HttpResponse
from django.shortcuts import redirect

logger = logging.getLogger("gatekeeper.audit")

CAMINHOS_LIVRES = (
    "/accounts/",
    "/login/",
    "/logout/",
    "/static/",
    "/media/",
)


def exige_mfa(user):
    """
    Fase 10.5: Exige MFA de quem pode alterar qualquer coisa — não importa por qual grupo recebeu a permissão.
    Verifica se o usuário é staff, superusuário ou possui qualquer permissão que não seja somente leitura ('view_*').
    """
    if user.is_staff or user.is_superuser:
        return True
    return any(not perm.split(".", 1)[1].startswith("view_") for perm in user.get_all_permissions())


class RequireMFAMiddleware:
    """
    Exige autenticação multifator (TOTP) para contas administrativas ou com privilégio de escrita.
    Avalia a permissão efetiva do usuário (exige_mfa) garantindo que qualquer usuário com capacidade
    de alteração seja forçado a cadastrar TOTP antes de acessar o sistema (CIS Safeguard 6.5).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if (
            user.is_authenticated
            and not request.path.startswith(CAMINHOS_LIVRES)
            and exige_mfa(user)
            and not Authenticator.objects.filter(user=user, type=Authenticator.Type.TOTP).exists()
        ):
            return redirect("mfa_activate_totp")

        return self.get_response(request)


class HealthCheckMiddleware:
    """
    Health check para Docker/orquestradores em /healthz/ (Fase 9.2).

    Fica no topo do MIDDLEWARE de propósito: responde antes da validação de ALLOWED_HOSTS,
    do redirecionamento HTTPS, da sessão, da autenticação e do MFA. Assim o `curl` interno
    do container (Host: 127.0.0.1, HTTP puro) funciona mesmo com o domínio real em
    ALLOWED_HOSTS e SECURE_SSL_REDIRECT ativo — e falha de verdade quando o banco cai,
    em vez de "passar" com um 301 como acontecia com /login/.

    Não lê request.get_host(), não abre sessão e não revela detalhes do erro.
    """

    PATH = "/healthz/"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path_info != self.PATH or request.method not in ("GET", "HEAD"):
            return self.get_response(request)

        try:
            connection.ensure_connection()
        except DatabaseError:
            logger.error("HEALTHCHECK_DB_UNAVAILABLE")
            response = HttpResponse("unavailable", status=503, content_type="text/plain")
        else:
            response = HttpResponse("ok", content_type="text/plain")

        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response
