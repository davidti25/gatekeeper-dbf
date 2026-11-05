"""
Custom Adapters para o django-allauth no GateKeeper-DBF.

Implementa o princípio de 'Negar por Padrão' (Deny by Default / CIS Controls v8):
- Desativação completa do cadastro público (/accounts/signup/)
- Contas somente podem ser criadas por Gestores de SecOps no Django Admin ou via CLI.
"""

from allauth.account.adapter import DefaultAccountAdapter


class NoSignupAccountAdapter(DefaultAccountAdapter):
    """
    Contas só são criadas por um Gestor SecOps no Django Admin ou via comandos de gestão CLI.
    Cadastro público (/accounts/signup/) é estritamente proibido (Deny by Default).
    """

    def is_open_for_signup(self, request):
        return False
