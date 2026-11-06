"""
Comando de Gestão para Envio de Lembretes Operacionais e Alertas de SLA (Fase 16.2).

Regras de Segurança:
- Conformidade com CIS Controls 5.3 / 5.5 e LGPD Art. 46.
- O e-mail contém estritamente o link corporativo seguro para o GateKeeper (exige login + MFA).
- NUNCA trafega nomes de sistemas, contas, credenciais ou dados pessoais por e-mail.
- Nenhum link de ação direta ('aprovar por e-mail').
- Suporte a configuração opcional via EMAIL_URL (django-environ).
"""

import logging

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand

from apps.governance.models import (
    CampanhaRevisao,
    ItemChecklistOffboarding,
    ItemRevisao,
    ProcessoOffboarding,
)

logger = logging.getLogger("gatekeeper.audit")


class Command(BaseCommand):
    help = "Envia lembretes de offboardings pendentes e revisões periódicas de acessos."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Simula o envio de e-mails sem dispará-los.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        base_url = getattr(settings, "GATEKEEPER_BASE_URL", "https://gatekeeper.empresa.com.br")
        sla_horas = getattr(settings, "OFFBOARDING_SLA_HORAS", 24)
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "gatekeeper@empresa.com.br")

        destinatarios_notificados = set()

        # 1. Offboardings em andamento e donos de sistemas com pendências
        procs_ativos = ProcessoOffboarding.objects.filter(
            status=ProcessoOffboarding.StatusOffboarding.INICIADO
        ).select_related("responsavel_ti")

        for proc in procs_ativos:
            if proc.responsavel_ti and proc.responsavel_ti.email:
                destinatarios_notificados.add(proc.responsavel_ti.email)

            # Donos dos sistemas envolvidos no checklist
            itens_pendentes = proc.itens_checklist.filter(
                status=ItemChecklistOffboarding.StatusItem.PENDENTE
            ).select_related("vinculo_acesso__sistema__dono")

            for item in itens_pendentes:
                dono = item.vinculo_acesso.sistema.dono
                if dono and dono.email:
                    destinatarios_notificados.add(dono.email)

        # 2. Revisões de acessos abertas com itens pendentes
        itens_revisao_pendentes = ItemRevisao.objects.filter(
            campanha__status=CampanhaRevisao.StatusCampanha.ABERTA,
            decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
        ).select_related("revisor")

        for item_rev in itens_revisao_pendentes:
            if item_rev.revisor and item_rev.revisor.email:
                destinatarios_notificados.add(item_rev.revisor.email)

        total_enviados = 0
        corpo_email = (
            "Olá,\n\n"
            "Você possui ações pendentes de governança e segurança corporativa no GateKeeper-DBF "
            "(processos de revogação de offboarding ou recertificação periódica de acessos).\n\n"
            "Para consultar os itens atribuídos e registrar suas decisões com segurança, acesse:\n"
            f"{base_url}\n\n"
            "Nota de Segurança (CIS Controls / LGPD):\n"
            "- Este e-mail não contém dados pessoais, nomes de sistemas ou contas corporativas.\n"
            "- A plataforma GateKeeper exige login autenticado com MFA (TOTP).\n"
            "- Nunca compartilhe suas credenciais corporativas.\n"
        )

        for email in destinatarios_notificados:
            if not dry_run:
                send_mail(
                    subject="[GateKeeper-DBF] Notificação de Ações Pendentes de Segurança",
                    message=corpo_email,
                    from_email=from_email,
                    recipient_list=[email],
                    fail_silently=True,
                )
            total_enviados += 1

        logger.info(
            "ALERT_REMINDERS_SENT",
            extra={
                "audit": {
                    "total_destinatarios": total_enviados,
                    "dry_run": dry_run,
                    "sla_horas_referencia": sla_horas,
                }
            },
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"[+] Lembretes processados com sucesso. Total de destinatários: {total_enviados} (dry-run: {dry_run})."
            )
        )
