"""
Comando de Auditoria e Saneamento de Identidades do GateKeeper-DBF.

Objetivo:
Revisar contas criadas no sistema, identificando usuários órfãos (sem grupos RBAC atribuídos,
sem privilégio de staff e sem MFA configurado).
Permite a desativação imediata para contenção preventiva (CIS Safeguard 5.3 / NIST IR).

Uso:
    python manage.py auditar_contas
    python manage.py auditar_contas --desativar
"""

import logging

from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger("gatekeeper.audit")
User = get_user_model()


class Command(BaseCommand):
    help = "Audita contas cadastradas identificando usuários sem perfil/grupo e sem MFA (CIS 5.3)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--desativar",
            action="store_true",
            help="Desativa imediatamente (is_active=False) contas ativas sem grupo ou privilégios atribuídos.",
        )

    def handle(self, *args, **options):
        desativar = options["desativar"]

        self.stdout.write(self.style.NOTICE("🔍 Iniciando auditoria de identidades e contas no GateKeeper-DBF...\n"))

        # Localiza usuários ativos sem nenhum grupo e sem privilégios de staff/superuser
        usuarios_orfaos = (
            User.objects.filter(is_active=True, is_staff=False, is_superuser=False, groups__isnull=True)
            .distinct()
            .order_by("date_joined")
        )

        total_encontrado = usuarios_orfaos.count()

        if total_encontrado == 0:
            self.stdout.write(
                self.style.SUCCESS(
                    "✅ Nenhuma conta órfã ou sem perfil atribuído foi encontrada. Diretório de identidades íntegro!"
                )
            )
            return

        self.stdout.write(
            self.style.WARNING(
                f"⚠️  Foram identificadas {total_encontrado} conta(s) ativas sem qualquer perfil RBAC atribuído:\n"
            )
        )

        cabecalho = f"{'ID':<6} | {'Usuário':<20} | {'E-mail':<30} | {'Criado em':<20} | {'MFA':<10}"
        self.stdout.write(cabecalho)
        self.stdout.write("-" * len(cabecalho))

        desativados_count = 0

        for u in usuarios_orfaos:
            tem_mfa = Authenticator.objects.filter(user=u, type=Authenticator.Type.TOTP).exists()
            mfa_str = "Sim" if tem_mfa else "Não"
            criado_em = timezone.localtime(u.date_joined).strftime("%d/%m/%Y %H:%M") if u.date_joined else "N/A"

            self.stdout.write(f"{u.id:<6} | {u.username:<20} | {u.email:<30} | {criado_em:<20} | {mfa_str:<10}")

            if desativar:
                u.is_active = False
                u.save(update_fields=["is_active"])
                desativados_count += 1
                logger.warning(
                    f"ACCOUNT_DEACTIVATED_BY_AUDIT: usuario='{u.username}' acao='DESATIVACAO_PREVENTIVA' operador='CLI_AUDITORIA'"
                )

        self.stdout.write("-" * len(cabecalho))

        if desativar:
            self.stdout.write(
                self.style.SUCCESS(
                    f"\n🛡️  Contenção Concluída: {desativados_count} conta(s) desativada(s) preventivamente."
                )
            )
        else:
            self.stdout.write(
                self.style.NOTICE(
                    "\n💡 Para desativar as contas identificadas acima, execute: python manage.py auditar_contas --desativar"
                )
            )
