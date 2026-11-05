"""
Utilitários de Segurança e Infraestrutura de Rede para o GateKeeper-DBF.
"""

from django.conf import settings


def get_client_ip(request):
    """
    Retorna o endereço IP confiável do cliente, mitigando IP Spoofing via cabeçalho X-Forwarded-For (CWE-345 / CIS 8.5).

    Mecânica de Defesa:
    - Se TRUSTED_PROXY_COUNT > 0, lê a cadeia de proxies da DIREITA para a ESQUERDA (cadeia[-n]),
      pois cada proxy confiável insere o IP do cliente imediatamente antes de si.
      O cliente só consegue forjar elementos mais à esquerda da cadeia.
    - Se TRUSTED_PROXY_COUNT == 0 (padrão fail-closed / sem proxy confiável declarado),
      o cabeçalho X-Forwarded-For é totalmente ignorado, retornando request.META['REMOTE_ADDR'].
    """
    if not request:
        return "UNKNOWN"

    trusted_proxy_count = getattr(settings, "TRUSTED_PROXY_COUNT", 0)
    if trusted_proxy_count > 0:
        xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if xff:
            cadeia = [p.strip() for p in xff.split(",") if p.strip()]
            if len(cadeia) >= trusted_proxy_count:
                return cadeia[-trusted_proxy_count]

    return request.META.get("REMOTE_ADDR", "UNKNOWN")
