"""
Testes Unitários & de Segurança para o Módulo de Governança & IAM (GateKeeper-DBF).

Cobre:
- Fase 0 (Emergência): Login obrigatório em todas as rotas (Secure by Default)
- Segregação de Funções (RBAC): Auditor, Analista TI e Gestor SecOps
- Não-Repúdio: Atribuição estrita a request.user (sem fallbacks automáticos)
- Mitigação de Stored XSS com data-confirm desacoplado
- Integridade do fluxo de revogação e cálculo de progresso de offboarding
- Fase 1 (Integridade & Auditoria): Simple-History, Proteção onDelete, Concorrência atômica, Validação LGPD
- Fase 2 (Hardening & Plataforma): Local-Only Assets, WhiteNoise, Strict CSP sem inline, Cookies de Sessão, Logs SOC
- Fase 3 (Identidade Forte): MFA / 2FA (TOTP), Rate Limiting anti-bruteforce, Blindagem admin.site.login
- Fase 4 (Qualidade & DevSecOps): Anti-N+1 Queries, Bloqueio de Acessos a Desligados, Cobertura Rigorosa
"""

import json
import logging
import re
from pathlib import Path
from unittest import mock

from allauth.mfa.models import Authenticator
from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.signals import user_login_failed
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.db import OperationalError
from django.db.models import ProtectedError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.governance import urls as gov_urls

from .forms import RevogacaoItemForm
from .logging import JSONAuditFormatter
from .models import (
    Cargo,
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    Localidade,
    PerfilAcesso,
    ProcessoOffboarding,
    Sistema,
    VinculoAcesso,
)
from .services import iniciar_offboarding, revogar_item_checklist
from .utils import get_client_ip

User = get_user_model()


class GovernanceSecurityAndModelTests(TestCase):
    def setUp(self):
        self.client = Client()

        # Grupos RBAC criados pela migração 0003
        self.grupo_auditor = Group.objects.get(name="Auditor")
        self.grupo_analista = Group.objects.get(name="Analista TI")
        self.grupo_gestor = Group.objects.get(name="Gestor SecOps")

        # Usuários por Perfil
        self.user_auditor = User.objects.create_user(
            username="auditor.externo", email="auditor@empresa.com.br", password="ComplexPassword123!"
        )
        self.user_auditor.groups.add(self.grupo_auditor)

        self.user_analista = User.objects.create_user(
            username="analista.secops", email="secops@empresa.com.br", password="ComplexPassword123!"
        )
        self.user_analista.groups.add(self.grupo_analista)
        Authenticator.objects.create(
            user=self.user_analista, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        self.user_gestor = User.objects.create_user(
            username="gestor.ciso", email="ciso@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.user_gestor.groups.add(self.grupo_gestor)
        Authenticator.objects.create(
            user=self.user_gestor, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        # Localidade & Setor
        self.matriz = Localidade.objects.create(
            nome="Sede São Paulo", codigo="SP-MATRIZ", cidade="São Paulo", estado="SP"
        )
        self.ti = Departamento.objects.create(
            nome="Tecnologia da Informação", sigla="TI", descricao="Setor de TI e Cibersegurança"
        )
        self.cargo = Cargo.objects.create(nome="Analista de SOC", departamento=self.ti)

        # Sistemas
        self.vpn = Sistema.objects.create(
            nome="VPN Corporativa WireGuard",
            tipo=Sistema.TipoSistema.VPN,
            criticidade=Sistema.Criticidade.ALTA,
            armazena_dados_lgpd=False,
            gestor_responsavel="Equipe de SecOps",
            instrucoes_revogacao="Remover chave pública do servidor WireGuard.",
        )
        self.perfil_vpn = PerfilAcesso.objects.create(
            sistema=self.vpn, nome="Acesso Full SOC", nivel_privilegio=PerfilAcesso.NivelPrivilegio.ADMIN
        )

        self.erp = Sistema.objects.create(
            nome="ERP Corporativo",
            tipo=Sistema.TipoSistema.SAAS,
            criticidade=Sistema.Criticidade.CRITICA,
            armazena_dados_lgpd=True,
            gestor_responsavel="TI Interna",
            instrucoes_revogacao="Inativar cadastro do usuário no painel master.",
        )

        # Colaborador
        self.colaborador = Colaborador.objects.create(
            nome_completo="Carlos Santos",
            matricula="TI-0042",
            email_corporativo="carlos.santos@empresa.com.br",
            localidade=self.matriz,
            departamento=self.ti,
            cargo=self.cargo,
            status=Colaborador.StatusColaborador.ATIVO,
            data_admissao=timezone.now().date(),
        )

    def test_01_autenticacao_obrigatoria_redireciona_anonimos(self):
        """0.1: Garante que qualquer acesso anônimo é redirecionado para a tela de login (Secure by Default)."""
        rotas = [
            reverse("dashboard"),
            reverse("colaborador_list"),
            reverse("colaborador_detail", kwargs={"pk": self.colaborador.pk}),
            reverse("sistema_list"),
            reverse("matriz_acesso"),
            reverse("offboarding_list"),
        ]

        for rota in rotas:
            resp = self.client.get(rota)
            self.assertEqual(resp.status_code, 302, f"Rota {rota} permitiu acesso sem login!")
            self.assertIn(reverse("login"), resp.headers["Location"])

    def test_02_tela_de_login_disponivel_sem_autenticacao(self):
        """Garante que a tela de login está acessível publicamente com formulário CSRF e inputs."""
        resp = self.client.get(reverse("login"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'name="login"')
        self.assertContains(resp, 'name="password"')
        self.assertContains(resp, "csrfmiddlewaretoken")

    def test_03_segregacao_funcoes_auditor_apenas_leitura(self):
        """0.2: Usuário do grupo Auditor visualiza painéis, mas é impedido de executar offboarding (403 Forbidden)."""
        self.client.force_login(self.user_auditor)

        # Leitura permitida
        self.assertEqual(self.client.get(reverse("dashboard")).status_code, 200)
        self.assertEqual(self.client.get(reverse("colaborador_list")).status_code, 200)
        self.assertEqual(self.client.get(reverse("sistema_list")).status_code, 200)

        # Escrita/Ação bloqueada com 403 Forbidden
        resp_iniciar = self.client.post(
            reverse("iniciar_offboarding", kwargs={"pk": self.colaborador.pk}),
            {"motivo_desligamento": "Auditor tentando desligar"},
        )
        self.assertEqual(resp_iniciar.status_code, 403)

    def test_04_analista_ti_executa_offboarding_com_nao_repudio_estrito(self):
        """0.2 e 0.3: Analista TI possui permissão para executar offboarding e seu login é gravado estritamente."""
        self.client.force_login(self.user_analista)

        # Concede acesso
        v = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.vpn,
            identificador_conta="carlos.vpn",
            concedido_por=self.user_gestor,
        )

        # Inicia Offboarding
        resp_iniciar = self.client.post(
            reverse("iniciar_offboarding", kwargs={"pk": self.colaborador.pk}),
            {"motivo_desligamento": "Desligamento formal test"},
        )
        self.assertEqual(resp_iniciar.status_code, 302)

        processo = ProcessoOffboarding.objects.get(colaborador=self.colaborador)
        # Não-repúdio: o responsável gravado DEVE ser estritamente self.user_analista
        self.assertEqual(processo.responsavel_ti, self.user_analista)

        # Revoga item
        item = processo.itens_checklist.first()
        resp_revogar = self.client.post(
            reverse("revogar_item_offboarding", kwargs={"pk": processo.pk, "item_id": item.pk}),
            {"evidencia_revogacao": "Ticket GLPI #5555"},
        )
        self.assertEqual(resp_revogar.status_code, 302)

        item.refresh_from_db()
        v.refresh_from_db()

        # Não-repúdio na revogação do checklist e no vínculo de acesso
        self.assertEqual(item.responsavel_revogacao, self.user_analista)
        self.assertEqual(v.revogado_por, self.user_analista)
        self.assertEqual(v.status, VinculoAcesso.StatusAcesso.REVOGADO)

    def test_05_neutralizacao_stored_xss_data_confirm(self):
        """0.4: Valida que payloads XSS em nome de colaborador não são inseridos em tags onclick executáveis."""
        self.client.force_login(self.user_analista)

        # Cria colaborador com payload de quebra de JavaScript
        colab_xss = Colaborador.objects.create(
            nome_completo="Ataque'); alert('xss'); ('",
            matricula="SEC-9999",
            email_corporativo="hacker@empresa.com.br",
            localidade=self.matriz,
            departamento=self.ti,
            cargo=self.cargo,
            status=Colaborador.StatusColaborador.ATIVO,
            data_admissao=timezone.now().date(),
        )

        resp = self.client.get(reverse("colaborador_detail", kwargs={"pk": colab_xss.pk}))
        self.assertEqual(resp.status_code, 200)

        # Não deve haver onclick com código inline
        self.assertNotContains(resp, 'onclick="return confirm')
        # Deve utilizar o atributo desacoplado data-confirm
        self.assertContains(resp, "data-confirm=")

    def test_06_master_root_acesso_total(self):
        """Valida que o usuário master root (superuser) possui acesso e execução irrestrita em todos os módulos."""
        root_user = User.objects.create_superuser(
            username="root.test", email="root.test@gatekeeper.local", password="RootDev2026!"
        )
        Authenticator.objects.create(user=root_user, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"})
        self.client.force_login(root_user)

        # Acesso às telas principais
        self.assertEqual(self.client.get(reverse("dashboard")).status_code, 200)
        self.assertEqual(self.client.get(reverse("colaborador_list")).status_code, 200)
        self.assertEqual(self.client.get(reverse("sistema_list")).status_code, 200)
        self.assertEqual(self.client.get(reverse("matriz_acesso")).status_code, 200)

        # Execução de ação privilegiada
        resp = self.client.post(
            reverse("iniciar_offboarding", kwargs={"pk": self.colaborador.pk}),
            {"motivo_desligamento": "Root override test"},
        )
        self.assertEqual(resp.status_code, 302)
        processo = ProcessoOffboarding.objects.get(colaborador=self.colaborador)
        self.assertEqual(processo.responsavel_ti, root_user)


class Phase1AuditAndIntegrityTests(TestCase):
    """
    Testes de Integridade da Auditoria & Regras de Negócio (Fase 1).
    Valida:
    - 1.1: on_delete=models.PROTECT contra expurgo acidental de dados
    - 1.2: Rastreabilidade temporal com django-simple-history
    - 1.3: Transações atômicas, idempotência e bloqueio de concorrência
    - 1.4: Validação estrita de evidências em sistemas críticos e escopo LGPD
    - 1.5: Suporte a recontratação (UniqueConstraint condicional)
    """

    def setUp(self):
        self.client = Client()

        self.grupo_analista = Group.objects.get(name="Analista TI")
        self.user_analista = User.objects.create_user(
            username="secops.analyst", email="analyst@empresa.com.br", password="ComplexPassword123!"
        )
        self.user_analista.groups.add(self.grupo_analista)
        Authenticator.objects.create(
            user=self.user_analista, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        self.matriz = Localidade.objects.create(nome="Filial Salvador", codigo="SSA-01", cidade="Salvador", estado="BA")
        self.depto = Departamento.objects.create(
            nome="Operações Financeiras", sigla="FIN", descricao="Controladoria e Financeiro"
        )
        self.cargo = Cargo.objects.create(nome="Analista Financeiro Pleno", departamento=self.depto)

        self.sistema_critico = Sistema.objects.create(
            nome="Internet Banking PJ",
            tipo=Sistema.TipoSistema.SAAS,
            criticidade=Sistema.Criticidade.CRITICA,
            armazena_dados_lgpd=True,
            gestor_responsavel="Segurança da Informação",
        )

        self.sistema_interno = Sistema.objects.create(
            nome="Wiki Interna Redmine",
            tipo=Sistema.TipoSistema.ONPREM,
            criticidade=Sistema.Criticidade.BAIXA,
            armazena_dados_lgpd=False,
            gestor_responsavel="TI Suporte",
        )

        self.colaborador = Colaborador.objects.create(
            nome_completo="Mariana Oliveira",
            matricula="FIN-8812",
            email_corporativo="mariana.oliveira@empresa.com.br",
            localidade=self.matriz,
            departamento=self.depto,
            cargo=self.cargo,
            status=Colaborador.StatusColaborador.ATIVO,
            data_admissao=timezone.now().date(),
        )

    def test_10_protecao_exclusao_acidental_on_delete_protect(self):
        """1.1: Colaboradores com vínculos de acesso ou processos de offboarding não podem ser deletados (PROTECT)."""
        vinculo = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema_interno,
            identificador_conta="mariana.wiki",
            concedido_por=self.user_analista,
        )

        # Tentativa de exclusão do colaborador com vínculo deve falhar
        with self.assertRaises(ProtectedError):
            self.colaborador.delete()

        # Cria processo e item de checklist
        processo = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        )
        ItemChecklistOffboarding.objects.create(processo=processo, vinculo_acesso=vinculo)

        # Tentativa de exclusão do vínculo com item no checklist deve falhar
        with self.assertRaises(ProtectedError):
            vinculo.delete()

    def test_11_bloqueio_concessao_acesso_colaborador_desligado_ou_em_offboarding(self):
        """1.1: Regra de negócio impede conceder novos acessos a colaboradores desligados ou em offboarding."""
        # 1. Colaborador em processo de offboarding ativo
        ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        )

        novo_vinculo = VinculoAcesso(
            colaborador=self.colaborador,
            sistema=self.sistema_critico,
            identificador_conta="mariana.banking",
            concedido_por=self.user_analista,
        )
        with self.assertRaises(ValidationError) as ctx:
            novo_vinculo.clean()
        self.assertIn("em processo de offboarding", str(ctx.exception))

        # 2. Colaborador desligado
        self.colaborador.status = Colaborador.StatusColaborador.DESLIGADO
        self.colaborador.save()

        novo_vinculo_desligado = VinculoAcesso(
            colaborador=self.colaborador,
            sistema=self.sistema_interno,
            identificador_conta="mariana.wiki2",
            concedido_por=self.user_analista,
        )
        with self.assertRaises(ValidationError) as ctx:
            novo_vinculo_desligado.clean()
        self.assertIn("colaborador já desligado", str(ctx.exception))

    def test_12_servico_revogacao_atomica_e_idempotencia(self):
        """1.3: Serviço revogar_item_checklist executa atomicamente e rejeita sobrescrita de itens já resolvidos."""
        vinculo = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema_interno,
            identificador_conta="mariana.wiki",
            concedido_por=self.user_analista,
        )
        processo = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        )
        item = ItemChecklistOffboarding.objects.create(processo=processo, vinculo_acesso=vinculo)

        # 1. Primeira execução: Sucesso
        item_revogado, proc_atualizado = revogar_item_checklist(
            item_id=item.pk,
            responsavel=self.user_analista,
            evidencia="Ticket ITSM #10293",
            observacao="Conta desativada",
            status=ItemChecklistOffboarding.StatusItem.REVOGADO,
        )
        self.assertEqual(item_revogado.status, ItemChecklistOffboarding.StatusItem.REVOGADO)
        self.assertTrue(item_revogado.revogado)
        self.assertEqual(proc_atualizado.status, ProcessoOffboarding.StatusOffboarding.CONCLUIDO)

        # 2. Segunda execução (tentativa de double submit/repetição): Deve falhar por idempotência
        with self.assertRaises(ValidationError) as ctx:
            revogar_item_checklist(
                item_id=item.pk,
                responsavel=self.user_analista,
                evidencia="Outro ticket",
                status=ItemChecklistOffboarding.StatusItem.REVOGADO,
            )
        self.assertIn("já foi finalizado anteriormente", str(ctx.exception))

    def test_13_validacao_formulario_evidencia_obrigatoria_sistemas_criticos_e_lgpd(self):
        """1.4: RevogacaoItemForm exige evidência em sistemas críticos/LGPD e rejeita descrições genéricas."""
        vinculo_critico = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema_critico,
            identificador_conta="mariana.ib",
            concedido_por=self.user_analista,
        )
        processo = ProcessoOffboarding.objects.create(colaborador=self.colaborador, responsavel_ti=self.user_analista)
        item_critico = ItemChecklistOffboarding.objects.create(processo=processo, vinculo_acesso=vinculo_critico)

        # 1. Sem evidência em sistema crítico/LGPD: Inválido
        form_vazio = RevogacaoItemForm(data={"status": "REVOGADO", "evidencia_revogacao": ""}, item=item_critico)
        self.assertFalse(form_vazio.is_valid())
        self.assertIn("evidencia_revogacao", form_vazio.errors)

        # 2. Com evidência genérica ("revogado manualmente"): Inválido
        form_generico = RevogacaoItemForm(
            data={"status": "REVOGADO", "evidencia_revogacao": "Revogado manualmente"}, item=item_critico
        )
        self.assertFalse(form_generico.is_valid())
        self.assertIn("evidencia_revogacao", form_generico.errors)

        # 3. Com evidência auditável (Ticket #...): Válido
        form_valido = RevogacaoItemForm(
            data={"status": "REVOGADO", "evidencia_revogacao": "Ticket GLPI #8841 - Chave revogada"}, item=item_critico
        )
        self.assertTrue(form_valido.is_valid())

    def test_14_rastreabilidade_historica_simple_history(self):
        """1.2: django-simple-history grava snapshots temporais de alterações em entidades sensíveis."""
        # Altera dados do colaborador
        self.colaborador.nome_completo = "Mariana Oliveira Santos"
        self.colaborador.save()

        # Deve haver 2 registros no histórico (criação e atualização)
        historico = self.colaborador.history.all()
        self.assertGreaterEqual(historico.count(), 2)
        self.assertEqual(historico[0].nome_completo, "Mariana Oliveira Santos")
        self.assertEqual(historico[1].nome_completo, "Mariana Oliveira")

    def test_15_suporte_recontratacao_colaborador(self):
        """1.5: Suporte a recontratação com histórico preservado e sem colisão de UniqueConstraint."""
        # Primeiro ciclo: offboarding concluído
        processo_1 = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.CONCLUIDO,
            concluido_em=timezone.now(),
        )

        # Recontratação: Colaborador reativado
        self.colaborador.status = Colaborador.StatusColaborador.ATIVO
        self.colaborador.save()

        # Segundo ciclo de offboarding futuro: Deve ser permitido criar novo processo ativo
        processo_2 = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        )
        self.assertIsNotNone(processo_2.pk)
        self.assertNotEqual(processo_1.pk, processo_2.pk)
        self.assertEqual(self.colaborador.processos_offboarding.count(), 2)


class Phase2PlatformAndHardeningTests(TestCase):
    """
    Testes de Plataforma & Hardening de Configuração (Fase 2).
    Valida:
    - 2.3: Content Security Policy (CSP) sem 'unsafe-inline'
    - 2.3: Front-end local desvinculado de CDNs externas (LGPD / Supply Chain)
    - 2.4: Hardening de sessão, cookies e configurações de deploy
    - 2.4: Trilha de auditoria SOC em sinais de autenticação
    """

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="soc.auditor", email="soc@empresa.com.br", password="ComplexPassword123!"
        )
        grupo_auditor = Group.objects.get(name="Auditor")
        self.user.groups.add(grupo_auditor)

    def test_20_csp_headers_sem_unsafe_inline(self):
        """2.3: Cabeçalho Content-Security-Policy presente e bloqueando inline scripts externos."""
        resp = self.client.get(reverse("login"))
        self.assertEqual(resp.status_code, 200)

        self.assertIn("Content-Security-Policy", resp.headers)
        csp = resp.headers["Content-Security-Policy"]

        # default-src 'self'
        self.assertIn("default-src 'self'", csp)
        # script-src 'self' sem 'unsafe-inline'
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("'unsafe-inline'", csp)
        # frame-ancestors 'none' (anti-clickjacking)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_21_recursos_estaticos_locais_sem_cdns_externos(self):
        """2.3: Front-end servido 100% de static/ sem dependência de CDNs ou envio de dados/IP para terceiros (LGPD)."""
        self.client.force_login(self.user)
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.status_code, 200)

        # Não deve haver conexões externas para Google Fonts, CDN Tailwind ou Unpkg
        self.assertNotContains(resp, "cdn.tailwindcss.com")
        self.assertNotContains(resp, "unpkg.com")
        self.assertNotContains(resp, "fonts.googleapis.com")
        self.assertNotContains(resp, "fonts.gstatic.com")

        # Deve conter as rotas locais compiladas e servidas pelo WhiteNoise (com ou sem hash)
        content = resp.content.decode()
        self.assertIn("/static/fonts/fonts.", content)
        self.assertIn("/static/css/tailwind.min.", content)
        self.assertIn("/static/vendor/lucide.min.", content)
        self.assertIn("/static/js/app.", content)

    def test_22_sessao_e_hardening_cookies(self):
        """2.4: Validação de cookies de sessão de 8 horas e isolamento HttpOnly."""
        from django.conf import settings

        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)
        self.assertEqual(settings.SESSION_COOKIE_AGE, 28800)
        self.assertTrue(settings.SESSION_EXPIRE_AT_BROWSER_CLOSE)
        self.assertEqual(settings.X_FRAME_OPTIONS, "DENY")
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)

    def test_23_trilha_auditoria_soc_sinais(self):
        """2.4 / 7.2: Eventos de autenticação disparam logs estruturados em JSON para ingestão em SIEM."""
        from .logging import JSONAuditFormatter

        with self.assertLogs("gatekeeper.audit", level="INFO") as cm:
            # Login com sucesso
            self.client.login(username="soc.auditor", password="ComplexPassword123!")
            # Logout
            self.client.logout()

        events = [r.getMessage() for r in cm.records]
        self.assertIn("AUTH_LOGIN_SUCCESS", events)
        self.assertIn("AUTH_LOGOUT", events)

        # Valida estruturação JSON com JSONAuditFormatter (CWE-117)
        formatter = JSONAuditFormatter()
        login_record = next(r for r in cm.records if r.getMessage() == "AUTH_LOGIN_SUCCESS")
        login_json = json.loads(formatter.format(login_record))
        self.assertEqual(login_json["event"], "AUTH_LOGIN_SUCCESS")
        self.assertEqual(login_json["usuario"], "soc.auditor")


class Phase3StrongIdentityAndMFATests(TestCase):
    """
    Testes de Segurança para Fase 3: Identidade Forte & Autenticação Multi-Fator (MFA).

    Cobre:
    - 3.1: Integração com django-allauth e MFA (TOTP e Recovery Codes).
    - 3.1: Proteção contra Brute Force (ACCOUNT_RATE_LIMITS = 5 tentativas em 5 min).
    - 3.1: Blindagem de /admin/login/ via secure_admin_login (redireciona para login centralizado).
    - 3.1: Isolamento de rotas MFA: não autenticado é redirecionado; autenticado acessa o hub.
    - 3.1: Disponibilidade dos modelos de MFA e integridade de e-mails de auditoria.
    """

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="soc.analyst", email="soc.analyst@empresa.com.br", password="ComplexPassword123!"
        )

    def test_30_admin_login_protegido_secure_admin_login(self):
        """3.1: /admin/login/ redireciona usuários não autenticados para a tela segura com MFA e rate limiting."""
        resp = self.client.get("/admin/login/")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login/", resp.get("Location"))
        self.assertIn("next=%2Fadmin%2Flogin%2F", resp.get("Location"))

    def test_31_mfa_endpoints_acessiveis_e_protegidos(self):
        """3.1: Painel MFA /accounts/2fa/ exige login prévio e responde 200 para usuário autenticado."""
        # Não autenticado -> Redirecionado para o login
        resp_unauth = self.client.get(reverse("mfa_index"))
        self.assertEqual(resp_unauth.status_code, 302)
        self.assertIn("/login/", resp_unauth.get("Location"))

        # Autenticado -> Acessa painel MFA com layout SOC
        self.client.force_login(self.user)
        resp_auth = self.client.get(reverse("mfa_index"))
        self.assertEqual(resp_auth.status_code, 200)
        self.assertContains(resp_auth, "Autenticação de dois fatores")
        self.assertContains(resp_auth, "/accounts/2fa/totp/activate/")
        self.assertContains(resp_auth, "Códigos de recuperação")

    @override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
    def test_32_rate_limit_tentativas_excessivas_de_login(self):
        """3.1: Tentativas consecutivas de login incorreto disparam rate limiting (MITRE ATT&CK T1110)."""
        login_url = reverse("account_login")

        # 5 tentativas incorretas consecutivas
        for _ in range(5):
            resp = self.client.post(login_url, {"login": "soc.analyst", "password": "WrongPassword!"})
            self.assertEqual(resp.status_code, 200)

        # 6ª tentativa deve ser barrada pelo allauth rate limiter
        resp_blocked = self.client.post(login_url, {"login": "soc.analyst", "password": "WrongPassword!"})
        self.assertEqual(resp_blocked.status_code, 200)
        self.assertContains(resp_blocked, "Muitas tentativas de login falharam")

    def test_33_mfa_models_migrados_e_disponiveis(self):
        """3.1: Modelos de EmailAddress e Authenticator (TOTP/Recovery) operacionais no banco."""
        from allauth.account.models import EmailAddress
        from allauth.mfa.models import Authenticator

        # Criação de email associado
        email_record = EmailAddress.objects.create(user=self.user, email=self.user.email, verified=True, primary=True)
        self.assertEqual(EmailAddress.objects.filter(user=self.user).count(), 1)
        self.assertTrue(email_record.verified)

        # Tabela de autenticadores MFA está vazia inicialmente para o usuário
        self.assertEqual(Authenticator.objects.filter(user=self.user).count(), 0)

    def test_34_totp_form_preserva_segredo_na_sessao(self):
        """3.1: GateKeeperActivateTOTPForm mantém o segredo e QR Code estáveis entre recarregamentos."""
        from allauth.core.context import request_context
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.test import RequestFactory

        from apps.governance.forms import GateKeeperActivateTOTPForm

        rf = RequestFactory()
        req = rf.get(reverse("mfa_activate_totp"))
        SessionMiddleware(lambda r: None).process_request(req)
        with request_context(req):
            f1 = GateKeeperActivateTOTPForm(user=self.user)
            segredo1 = f1.secret
            # Simula F5 / recarregamento da tela de ativação
            f2 = GateKeeperActivateTOTPForm(user=self.user)
            segredo2 = f2.secret
            self.assertEqual(segredo1, segredo2, "O segredo do TOTP não deve mudar em requisições consecutivas.")


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class Phase4QualityDevSecOpsAndPerformanceTests(TestCase):
    """
    Testes Unitários e de Performance para Fase 4: Qualidade & DevSecOps.

    Cobre:
    - 4.1: Validação de Regra de Negócio: Bloqueio estrito de concessão de acessos a desligados ou em offboarding.
    - 4.3: Desempenho & Anti-N+1: Propriedades anotadas em lote nas listagens (Colaboradores, Offboarding, Sistemas).
    """

    def setUp(self):
        self.client = Client()
        self.grupo_analista = Group.objects.get(name="Analista TI")
        self.user = User.objects.create_user(
            username="devsecops.analyst", email="devsecops@empresa.com.br", password="ComplexPassword123!"
        )
        self.user.groups.add(self.grupo_analista)
        Authenticator.objects.create(user=self.user, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"})

        self.depto = Departamento.objects.create(nome="Engenharia de Software", sigla="ENG")
        self.cargo = Cargo.objects.create(nome="Engenheiro DevSecOps", departamento=self.depto)
        self.localidade = Localidade.objects.create(nome="Salvador HQ", codigo="SSA-01", cidade="Salvador", estado="BA")
        self.sistema = Sistema.objects.create(
            nome="GitLab Enterprise",
            tipo=Sistema.TipoSistema.ONPREM,
            criticidade=Sistema.Criticidade.ALTA,
            tipo_autenticacao=Sistema.TipoAutenticacao.INDIVIDUAL,
        )

    def test_40_bloqueio_concessao_acesso_a_colaborador_desligado(self):
        """4.1: Impede concessão de novos acessos ATIVOS a colaborador com status DESLIGADO."""
        colaborador_desligado = Colaborador.objects.create(
            nome_completo="Lucas Ex-Funcionario",
            matricula="MAT-DESLIGADO-01",
            email_corporativo="lucas.ex@empresa.com.br",
            departamento=self.depto,
            cargo=self.cargo,
            localidade=self.localidade,
            data_admissao=timezone.localdate(),
            status=Colaborador.StatusColaborador.DESLIGADO,
            data_desligamento=timezone.localdate(),
        )

        vinculo = VinculoAcesso(
            colaborador=colaborador_desligado,
            sistema=self.sistema,
            identificador_conta="lucas.gitlab",
            status=VinculoAcesso.StatusAcesso.ATIVO,
            concedido_por=self.user,
        )

        with self.assertRaises(ValidationError) as ctx:
            vinculo.save()

        self.assertIn("Não é permitido conceder novos acessos a um colaborador já desligado", str(ctx.exception))

    def test_41_bloqueio_concessao_acesso_a_colaborador_em_offboarding(self):
        """4.1: Impede concessão de novos acessos a colaborador com offboarding em andamento."""
        colaborador_offboarding = Colaborador.objects.create(
            nome_completo="Patricia Em Offboarding",
            matricula="MAT-OFFB-01",
            email_corporativo="patricia.offb@empresa.com.br",
            departamento=self.depto,
            cargo=self.cargo,
            localidade=self.localidade,
            data_admissao=timezone.localdate(),
            status=Colaborador.StatusColaborador.ATIVO,
        )

        # Inicia processo de offboarding
        ProcessoOffboarding.objects.create(
            colaborador=colaborador_offboarding,
            responsavel_ti=self.user,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
            observacoes="Offboarding em andamento",
        )

        vinculo = VinculoAcesso(
            colaborador=colaborador_offboarding,
            sistema=self.sistema,
            identificador_conta="patricia.gitlab",
            status=VinculoAcesso.StatusAcesso.ATIVO,
            concedido_por=self.user,
        )

        with self.assertRaises(ValidationError) as ctx:
            vinculo.save()

        self.assertIn(
            "Não é permitido conceder novos acessos a um colaborador em processo de offboarding", str(ctx.exception)
        )

    def test_42_otimizacao_queries_anti_n_plus_one_listagem_colaboradores(self):
        """4.3: Listagem de colaboradores utiliza anotação _total_acessos_ativos sem disparar N+1 queries."""
        # Cria 5 colaboradores com múltiplos vínculos
        for i in range(5):
            c = Colaborador.objects.create(
                nome_completo=f"Colaborador Teste {i}",
                matricula=f"MAT-TEST-{i}",
                email_corporativo=f"teste{i}@empresa.com.br",
                departamento=self.depto,
                cargo=self.cargo,
                localidade=self.localidade,
                data_admissao=timezone.localdate(),
                status=Colaborador.StatusColaborador.ATIVO,
            )
            VinculoAcesso.objects.create(
                colaborador=c,
                sistema=self.sistema,
                identificador_conta=f"conta.teste.{i}",
                status=VinculoAcesso.StatusAcesso.ATIVO,
                concedido_por=self.user,
            )

        self.client.force_login(self.user)
        resp = self.client.get(reverse("colaborador_list"))
        self.assertEqual(resp.status_code, 200)

        # Verifica se os colaboradores na lista têm o atributo anotado
        colaboradores_na_view = resp.context["colaboradores"]
        for colab in colaboradores_na_view:
            self.assertTrue(hasattr(colab, "_total_acessos_ativos"))
            self.assertEqual(colab.total_acessos_ativos, colab._total_acessos_ativos)

    def test_43_otimizacao_queries_anti_n_plus_one_listagem_offboarding(self):
        """4.3: Listagem de offboarding utiliza anotações _total_itens e _total_revogados sem N+1 queries."""
        c = Colaborador.objects.create(
            nome_completo="Offboarded Colab Test",
            matricula="MAT-OFF-TEST",
            email_corporativo="offb@empresa.com.br",
            departamento=self.depto,
            cargo=self.cargo,
            localidade=self.localidade,
            data_admissao=timezone.localdate(),
            status=Colaborador.StatusColaborador.ATIVO,
        )
        v = VinculoAcesso.objects.create(
            colaborador=c,
            sistema=self.sistema,
            identificador_conta="offb.gitlab",
            status=VinculoAcesso.StatusAcesso.ATIVO,
            concedido_por=self.user,
        )
        proc = ProcessoOffboarding.objects.create(
            colaborador=c,
            responsavel_ti=self.user,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
            observacoes="Teste N+1",
        )
        ItemChecklistOffboarding.objects.create(
            processo=proc,
            vinculo_acesso=v,
            status=ItemChecklistOffboarding.StatusItem.REVOGADO,
            evidencia_revogacao="Audit Ticket #999",
            responsavel_revogacao=self.user,
        )

        self.client.force_login(self.user)
        resp = self.client.get(reverse("offboarding_list"))
        self.assertEqual(resp.status_code, 200)

        processos_na_view = resp.context["processos"]
        for p in processos_na_view:
            self.assertTrue(hasattr(p, "_total_itens"))
            self.assertTrue(hasattr(p, "_total_revogados"))
            self.assertTrue(hasattr(p, "_total_resolvidos"))
            self.assertEqual(p.total_itens, p._total_itens)
            self.assertEqual(p.total_revogados, p._total_revogados)


class Phase5EmergencyEntryProtectionTests(TestCase):
    """
    Testes de Segurança para Fase 5: Emergência — Fechar as Portas de Entrada (Plano v2).

    Cobre:
    - 5.1: Desativação do cadastro público (signup): NoSignupAccountAdapter bloqueia criação de contas via web.
    - 5.2: DashboardView exige permissão estrita 'governance.view_colaborador'.
    - 5.2 (Catraca): 100% das rotas da governança retornam 403 para usuário sem grupo (Fail-Closed).
    - 5.3: RequireMFAMiddleware: perfis de escrita (Analista TI, Gestor SecOps, staff) são forçados a cadastrar TOTP.
    - 5.4: Comando auditar_contas: identifica e desativa preventivamente contas órfãs sem grupos e sem MFA.
    """

    def setUp(self):
        self.client = Client()

        # Grupos RBAC
        self.grupo_auditor = Group.objects.get(name="Auditor")
        self.grupo_analista = Group.objects.get(name="Analista TI")
        self.grupo_gestor = Group.objects.get(name="Gestor SecOps")

        # Usuários
        self.user_sem_grupo = User.objects.create_user(
            username="usuario.intruso", email="intruso@externo.com", password="ComplexPassword123!"
        )

        self.user_auditor = User.objects.create_user(
            username="auditor.fase5", email="auditor.fase5@empresa.com.br", password="ComplexPassword123!"
        )
        self.user_auditor.groups.add(self.grupo_auditor)

        self.user_analista = User.objects.create_user(
            username="analista.fase5", email="analista.fase5@empresa.com.br", password="ComplexPassword123!"
        )
        self.user_analista.groups.add(self.grupo_analista)
        Authenticator.objects.create(
            user=self.user_analista, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        # Dados de apoio para rotas parametrizadas
        self.depto = Departamento.objects.create(nome="Segurança Operacional", sigla="SO")
        self.cargo = Cargo.objects.create(nome="Analista de Defesa", departamento=self.depto)
        self.localidade = Localidade.objects.create(nome="Recife SEC", codigo="REC-01", cidade="Recife", estado="PE")
        self.colaborador = Colaborador.objects.create(
            nome_completo="Fernando Ameaça",
            matricula="MAT-AMEACA-01",
            email_corporativo="fernando.ameaca@empresa.com.br",
            departamento=self.depto,
            cargo=self.cargo,
            localidade=self.localidade,
            data_admissao=timezone.localdate(),
            status=Colaborador.StatusColaborador.ATIVO,
        )
        self.sistema = Sistema.objects.create(
            nome="SIEM Splunk Enterprise",
            tipo=Sistema.TipoSistema.ONPREM,
            criticidade=Sistema.Criticidade.CRITICA,
            tipo_autenticacao=Sistema.TipoAutenticacao.INDIVIDUAL,
        )
        self.vinculo = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema,
            identificador_conta="fernando.siem",
            status=VinculoAcesso.StatusAcesso.ATIVO,
            concedido_por=self.user_analista,
        )
        self.processo = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
            observacoes="Offboarding para teste catraca",
        )
        self.item_checklist = ItemChecklistOffboarding.objects.create(
            processo=self.processo,
            vinculo_acesso=self.vinculo,
            status=ItemChecklistOffboarding.StatusItem.PENDENTE,
        )

    def test_51_cadastro_publico_desativado_no_signup_adapter(self):
        """5.1: Bloqueia registro de novas contas via /accounts/signup/ (Deny by Default / CIS 5.1)."""
        signup_url = reverse("account_signup")

        # GET deve renderizar aviso de cadastro desativado (signup_closed)
        resp_get = self.client.get(signup_url)
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, "Cadastro Público Desativado")

        # POST deve ser descartado sem criar usuário no banco
        dados_cadastro = {
            "username": "hacker.externo",
            "email": "hacker@evil.corp",
            "password1": "SenhaInvasao123!",
            "password2": "SenhaInvasao123!",
        }
        resp_post = self.client.post(signup_url, dados_cadastro)
        self.assertEqual(resp_post.status_code, 200)
        self.assertFalse(User.objects.filter(username="hacker.externo").exists())

    def test_52_dashboard_exige_permissao_estrita_view_colaborador(self):
        """5.2: DashboardView exige 'governance.view_colaborador' e bloqueia usuário autenticado sem grupos."""
        # Usuário autenticado sem grupo recebe 403 Forbidden
        self.client.force_login(self.user_sem_grupo)
        resp_bloqueado = self.client.get(reverse("dashboard"))
        self.assertEqual(resp_bloqueado.status_code, 403)

        # Usuário do grupo Auditor tem view_colaborador e acessa com 200 OK
        self.client.force_login(self.user_auditor)
        resp_autorizado = self.client.get(reverse("dashboard"))
        self.assertEqual(resp_autorizado.status_code, 200)

    def test_52_catraca_todas_rotas_governance_exigem_permissao(self):
        """5.2 (Catraca): 100% das rotas de governance retornam 403 para usuário sem grupo; novas rotas obrigam cadastro."""
        rotas_protegidas = {
            "dashboard": {},
            "colaborador_list": {},
            "colaborador_detail": {"pk": self.colaborador.pk},
            "iniciar_offboarding": {"pk": self.colaborador.pk},
            "sistema_list": {},
            "matriz_acesso": {},
            "offboarding_list": {},
            "offboarding_detail": {"pk": self.processo.pk},
            "revogar_item_offboarding": {"pk": self.processo.pk, "item_id": self.item_checklist.pk},
            "offboarding_relatorio": {"pk": self.processo.pk},
        }

        # Garante que nenhuma rota futura seja criada sem estar cadastrada no teste-catraca
        nomes_urls_governance = {p.name for p in gov_urls.urlpatterns}
        self.assertEqual(
            nomes_urls_governance,
            set(rotas_protegidas.keys()),
            "❌ ALERTA DE SEGURANÇA: Existe rota em governance/urls.py não registrada no teste-catraca!",
        )

        self.client.force_login(self.user_sem_grupo)
        for nome_rota, kwargs in rotas_protegidas.items():
            url = reverse(nome_rota, kwargs=kwargs)
            resp = self.client.get(url)
            self.assertEqual(
                resp.status_code,
                403,
                f"Falha de Autorização: Rota '{nome_rota}' ({url}) respondeu {resp.status_code} em vez de 403 para usuário sem perfil!",
            )

    def test_53_mfa_obrigatorio_para_escrita_e_staff(self):
        """5.3: Usuários com poder de escrita ou staff sem TOTP são redirecionados para ativação de MFA (CIS 6.5)."""
        analista_sem_mfa = User.objects.create_user(
            username="analista.pendente", email="pendente@empresa.com.br", password="ComplexPassword123!"
        )
        analista_sem_mfa.groups.add(self.grupo_analista)

        self.client.force_login(analista_sem_mfa)

        # Tentativa de acesso a rota do sistema deve ser redirecionada para ativação de TOTP
        resp = self.client.get(reverse("colaborador_list"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("mfa_activate_totp"), resp.get("Location"))

        # Após cadastrar TOTP, o acesso deve ser liberado imediatamente
        Authenticator.objects.create(
            user=analista_sem_mfa, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )
        resp_liberado = self.client.get(reverse("colaborador_list"))
        self.assertEqual(resp_liberado.status_code, 200)

        # Usuário Auditor (sem permissão de escrita e sem staff) não é forçado a ter MFA nesta fase
        self.client.force_login(self.user_auditor)
        resp_auditor = self.client.get(reverse("colaborador_list"))
        self.assertEqual(resp_auditor.status_code, 200)

    def test_54_comando_auditar_contas_identifica_e_desativa_orfaos(self):
        """5.4: Comando auditar_contas lista contas sem grupos/MFA e desativa preventivamente com flag --desativar."""
        from io import StringIO

        usuario_orfa = User.objects.create_user(
            username="conta.suspeita", email="suspeita@gmail.com", password="ComplexPassword123!"
        )
        self.assertTrue(usuario_orfa.is_active)

        # Execução padrão (modo visualização)
        out = StringIO()
        call_command("auditar_contas", stdout=out)
        conteudo = out.getvalue()
        self.assertIn("conta.suspeita", conteudo)
        self.assertIn("suspeita@gmail.com", conteudo)

        # Conta ainda permanece ativa
        usuario_orfa.refresh_from_db()
        self.assertTrue(usuario_orfa.is_active)

        # Execução com flag --desativar (contenção)
        out_desativar = StringIO()
        call_command("auditar_contas", "--desativar", stdout=out_desativar)
        self.assertIn("Contenção Concluída", out_desativar.getvalue())

        # Conta deve ter sido desativada no banco
        usuario_orfa.refresh_from_db()
        self.assertFalse(usuario_orfa.is_active)


class Phase6OffboardingIntegrityAndStateMachineTests(TestCase):
    """
    Testes de Integridade & Regras de Negócio para Fase 6: Fluxo de Offboarding (Plano v2).

    Cobre:
    - 6.1: Máquina de estados explícita: FALHA aceita retry (FALHA -> REVOGADO) concluindo o processo.
    - 6.1: Transições inválidas bloqueadas (REVOGADO é final; PENDENTE nunca é destino).
    - 6.2: 'Não Aplicável' encerra o vínculo (impede acesso ATIVO órfão) e exige justificativa >= 20 caracteres.
    - 6.2: Permissão exclusiva para 'marcar_nao_aplicavel' reservada ao Gestor SecOps.
    - 6.3: Concorrência e atomicidade no iniciar_offboarding() evitando duplicações.
    - 6.4: Relatório executivo à prova de contradição com alerta visual de inconsistência.
    """

    def setUp(self):
        self.client = Client()

        self.grupo_analista = Group.objects.get(name="Analista TI")
        self.grupo_gestor = Group.objects.get(name="Gestor SecOps")

        self.user_analista = User.objects.create_user(
            username="analista.fase6", email="analista.fase6@empresa.com.br", password="ComplexPassword123!"
        )
        self.user_analista.groups.add(self.grupo_analista)
        Authenticator.objects.create(
            user=self.user_analista, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        self.user_gestor = User.objects.create_user(
            username="gestor.fase6", email="gestor.fase6@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.user_gestor.groups.add(self.grupo_gestor)
        Authenticator.objects.create(
            user=self.user_gestor, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        self.depto = Departamento.objects.create(nome="Segurança da Informação", sigla="SEC")
        self.cargo = Cargo.objects.create(nome="Analista de Incidentes", departamento=self.depto)
        self.localidade = Localidade.objects.create(
            nome="Fortaleza SOC", codigo="FOR-01", cidade="Fortaleza", estado="CE"
        )

        self.colaborador = Colaborador.objects.create(
            nome_completo="Juliana Investigada",
            matricula="MAT-OFF-F6",
            email_corporativo="juliana.f6@empresa.com.br",
            departamento=self.depto,
            cargo=self.cargo,
            localidade=self.localidade,
            data_admissao=timezone.localdate(),
            status=Colaborador.StatusColaborador.ATIVO,
        )

        self.sistema = Sistema.objects.create(
            nome="AWS Cloud Production",
            tipo=Sistema.TipoSistema.SAAS,
            criticidade=Sistema.Criticidade.CRITICA,
            tipo_autenticacao=Sistema.TipoAutenticacao.INDIVIDUAL,
            armazena_dados_lgpd=True,
        )

        self.vinculo = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema,
            identificador_conta="juliana.aws",
            status=VinculoAcesso.StatusAcesso.ATIVO,
            concedido_por=self.user_gestor,
        )

        self.processo, _ = iniciar_offboarding(
            colaborador_id=self.colaborador.pk,
            responsavel=self.user_analista,
            motivo="Desligamento Fase 6",
        )
        self.item = self.processo.itens_checklist.first()

    def test_61_maquina_estados_retry_apos_falha_conclui_processo(self):
        """6.1: Item com FALHA aceita nova tentativa (FALHA -> REVOGADO) e conclui o processo."""
        # 1. Primeira tentativa resulta em FALHA (ex: API da AWS indisponível)
        item_falha, proc_pendente = revogar_item_checklist(
            item_id=self.item.pk,
            responsavel=self.user_analista,
            evidencia="API Timeout AWS Endpoint",
            observacao="Tentativa falhou devido a timeout externo",
            status=ItemChecklistOffboarding.StatusItem.FALHA,
        )
        self.assertEqual(item_falha.status, ItemChecklistOffboarding.StatusItem.FALHA)
        self.assertEqual(proc_pendente.status, ProcessoOffboarding.StatusOffboarding.PENDENTE)

        # 2. Nova tentativa após restauração do serviço transita para REVOGADO
        item_revogado, proc_concluido = revogar_item_checklist(
            item_id=self.item.pk,
            responsavel=self.user_analista,
            evidencia="Ticket AWS IAM #90219 - Chave excluída",
            observacao="Conta desativada com sucesso na segunda tentativa",
            status=ItemChecklistOffboarding.StatusItem.REVOGADO,
        )
        self.assertEqual(item_revogado.status, ItemChecklistOffboarding.StatusItem.REVOGADO)
        self.assertEqual(proc_concluido.status, ProcessoOffboarding.StatusOffboarding.CONCLUIDO)
        self.assertIsNotNone(proc_concluido.concluido_em)

    def test_61_maquina_estados_transicoes_invalidas_recusadas(self):
        """6.1: Transições ilegais na máquina de estados são bloqueadas com ValidationError."""
        # Item inicial é PENDENTE: não pode transitar para PENDENTE
        with self.assertRaises(ValidationError) as ctx:
            revogar_item_checklist(
                item_id=self.item.pk,
                responsavel=self.user_analista,
                evidencia="Evidência",
                status=ItemChecklistOffboarding.StatusItem.PENDENTE,
            )
        self.assertIn("Transição de status não permitida", str(ctx.exception))

        # Resolve o item para REVOGADO (estado terminal)
        revogar_item_checklist(
            item_id=self.item.pk,
            responsavel=self.user_analista,
            evidencia="Ticket ITSM #12345",
            status=ItemChecklistOffboarding.StatusItem.REVOGADO,
        )

        # Tentar reabrir item REVOGADO deve falhar
        with self.assertRaises(ValidationError) as ctx2:
            revogar_item_checklist(
                item_id=self.item.pk,
                responsavel=self.user_analista,
                evidencia="Tentando mudar",
                status=ItemChecklistOffboarding.StatusItem.FALHA,
            )
        self.assertIn("Transição de status não permitida", str(ctx2.exception))

    def test_62_nao_aplicavel_encerramento_vinculo_e_justificativa(self):
        """6.2: Não Aplicável exige justificativa >= 20 chars e encerra o vínculo (nenhum vínculo ativo residual)."""
        # Sem justificativa ou com menos de 20 caracteres -> Rejeitado
        with self.assertRaises(ValidationError) as ctx:
            revogar_item_checklist(
                item_id=self.item.pk,
                responsavel=self.user_gestor,
                evidencia="Sem evidência",
                observacao="Curta",
                status=ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL,
            )
        self.assertIn("mínimo de 20 caracteres", str(ctx.exception))

        # Com justificativa detalhada (>= 20 chars) -> Sucesso
        justificativa_valida = "Colaborador nunca utilizou console AWS; conta inexistente no IAM"
        item, proc = revogar_item_checklist(
            item_id=self.item.pk,
            responsavel=self.user_gestor,
            evidencia="",
            observacao=justificativa_valida,
            status=ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL,
        )
        self.assertEqual(item.status, ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL)
        self.assertEqual(proc.status, ProcessoOffboarding.StatusOffboarding.CONCLUIDO)

        # Invariante: o vínculo correspondente não pode permanecer ATIVO
        self.vinculo.refresh_from_db()
        self.assertEqual(self.vinculo.status, VinculoAcesso.StatusAcesso.REVOGADO)
        self.assertIn("Não aplicável:", self.vinculo.justificativa)

    def test_62_permissao_exclusiva_gestor_marcar_nao_aplicavel(self):
        """6.2: Analista TI sem permissão é barrado ao tentar marcar Não Aplicável; Gestor SecOps é autorizado."""
        revogar_url = reverse("revogar_item_offboarding", kwargs={"pk": self.processo.pk, "item_id": self.item.pk})

        # 1. Analista TI tenta postar NAO_APLICAVEL
        self.client.force_login(self.user_analista)
        resp_analista = self.client.post(
            revogar_url,
            {
                "status": ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL,
                "evidencia_revogacao": "",
                "observacao": "Justificativa detalhada de mais de 20 caracteres aqui",
            },
            follow=True,
        )
        self.assertContains(resp_analista, "Apenas o Gestor SecOps possui autorização")
        self.item.refresh_from_db()
        self.assertEqual(self.item.status, ItemChecklistOffboarding.StatusItem.PENDENTE)

        # 2. Gestor SecOps posta NAO_APLICAVEL com justificativa
        self.client.force_login(self.user_gestor)
        resp_gestor = self.client.post(
            revogar_url,
            {
                "status": ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL,
                "evidencia_revogacao": "",
                "observacao": "Justificativa detalhada de mais de 20 caracteres autorizada pelo CISO",
            },
            follow=True,
        )
        self.assertContains(resp_gestor, "resolvidos")
        self.item.refresh_from_db()
        self.assertEqual(self.item.status, ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL)

    def test_63_iniciar_offboarding_atomico_previne_duplicidade(self):
        """6.3: iniciar_offboarding atômico com select_for_update retorna processo existente sem duplicar."""
        proc1, criado1 = iniciar_offboarding(
            colaborador_id=self.colaborador.pk,
            responsavel=self.user_gestor,
            motivo="Offboarding primário",
        )
        self.assertFalse(criado1)
        self.assertEqual(proc1.pk, self.processo.pk)
        self.assertEqual(self.colaborador.processos_offboarding.count(), 1)

    def test_64_relatorio_alerta_inconsistencia_se_houver_vinculo_ativo(self):
        """6.4: Relatório executivo detecta quebra de invariante (acesso ATIVO residual) e exibe alerta visual."""
        # Conclui o item
        revogar_item_checklist(
            item_id=self.item.pk,
            responsavel=self.user_gestor,
            evidencia="Ticket GLPI #999",
            status=ItemChecklistOffboarding.StatusItem.REVOGADO,
        )
        self.processo.refresh_from_db()
        self.assertEqual(self.processo.status, ProcessoOffboarding.StatusOffboarding.CONCLUIDO)

        # Relatório consistente (normal)
        self.client.force_login(self.user_gestor)
        relatorio_url = reverse("offboarding_relatorio", kwargs={"pk": self.processo.pk})
        resp_normal = self.client.get(relatorio_url)
        self.assertEqual(resp_normal.status_code, 200)
        self.assertFalse(resp_normal.context["inconsistente"])
        self.assertNotContains(resp_normal, "PROCESSO INCONSISTENTE")

        # Simula inconsistência residual forçando status ATIVO no vínculo
        VinculoAcesso.objects.filter(pk=self.vinculo.pk).update(status=VinculoAcesso.StatusAcesso.ATIVO)

        resp_inconsistente = self.client.get(relatorio_url)
        self.assertEqual(resp_inconsistente.status_code, 200)
        self.assertTrue(resp_inconsistente.context["inconsistente"])
        self.assertContains(resp_inconsistente, "PROCESSO INCONSISTENTE — ACESSO ATIVO DETECTADO")
        self.assertContains(resp_inconsistente, "INCONSISTENTE (ACESSO ATIVO)")


class Phase7AuditAndTelemetryTests(TestCase):
    """
    Testes de Segurança para Fase 7: Trilha de Auditoria Confiável (SOC / SIEM).

    Cobre:
    - 7.1: Sanitização do IP do cliente e proteção contra IP Spoofing via X-Forwarded-For (CWE-345 / CIS 8.5)
    - 7.2: Logs estruturados em JSON e blindagem contra Log Injection via payloads multilinha (CWE-117)
    - 7.3: Emissão de eventos estruturados no ciclo de vida de offboarding
    """

    class MockRequest:
        def __init__(self, meta=None):
            self.META = meta or {}

    def test_71_ip_real_com_proxy_e_sem_proxy(self):
        """7.1: get_client_ip sanitiza IP lendo proxies da direita para a esquerda e ignora XFF quando count=0."""
        # 1. Requisição vazia ou nula
        self.assertEqual(get_client_ip(None), "UNKNOWN")

        # 2. Conexão direta sem proxy (TRUSTED_PROXY_COUNT = 0):
        # Atacante injeta X-Forwarded-For falso, mas REMOTE_ADDR prevalece (Fail-Closed)
        req_sem_proxy = self.MockRequest(
            {
                "HTTP_X_FORWARDED_FOR": "198.51.100.1, 203.0.113.55",
                "REMOTE_ADDR": "192.0.2.1",
            }
        )
        with override_settings(TRUSTED_PROXY_COUNT=0):
            ip_calculado = get_client_ip(req_sem_proxy)
            self.assertEqual(ip_calculado, "192.0.2.1", "Com proxy_count=0, XFF deve ser rigorosamente ignorado.")

        # 3. Atrás de 1 Proxy Reverso Confiável (ex: Caddy) (TRUSTED_PROXY_COUNT = 1):
        # O elemento mais à direita foi adicionado pelo proxy confiável
        req_1_proxy = self.MockRequest(
            {
                "HTTP_X_FORWARDED_FOR": "10.0.0.99, 203.0.113.195",
                "REMOTE_ADDR": "172.20.0.2",  # IP interno do container Caddy
            }
        )
        with override_settings(TRUSTED_PROXY_COUNT=1):
            ip_calculado = get_client_ip(req_1_proxy)
            self.assertEqual(ip_calculado, "203.0.113.195", "Deve selecionar o IP mais à direita da cadeia.")

        # 4. Atrás de 2 Proxies Confiáveis (ex: Cloudflare CDN + Caddy Local) (TRUSTED_PROXY_COUNT = 2):
        req_2_proxies = self.MockRequest(
            {
                "HTTP_X_FORWARDED_FOR": "1.1.1.1, 198.51.100.22, 172.67.1.1",
                "REMOTE_ADDR": "172.20.0.2",
            }
        )
        with override_settings(TRUSTED_PROXY_COUNT=2):
            ip_calculado = get_client_ip(req_2_proxies)
            self.assertEqual(ip_calculado, "198.51.100.22", "Deve selecionar o segundo IP a partir da direita.")

        # 5. Cadeia menor que o número de proxies confiáveis: fallback seguro para REMOTE_ADDR
        req_cadeia_curta = self.MockRequest(
            {
                "HTTP_X_FORWARDED_FOR": "203.0.113.1",
                "REMOTE_ADDR": "172.20.0.2",
            }
        )
        with override_settings(TRUSTED_PROXY_COUNT=3):
            ip_calculado = get_client_ip(req_cadeia_curta)
            self.assertEqual(ip_calculado, "172.20.0.2")

    def test_72_json_audit_formatter_anti_log_injection(self):
        """7.2: JSONAuditFormatter previne injeção de logs (CWE-117) escapando \\r e \\n em linha única."""
        record = logging.LogRecord(
            name="gatekeeper.audit",
            level=logging.WARNING,
            pathname="services.py",
            lineno=163,
            msg="OFFBOARDING_ITEM_REVOKED",
            args=(),
            exc_info=None,
        )
        # Payload malicioso com quebra de linha simulando falso evento de login
        payload_malicioso = (
            "Chamado GLPI #999\r\nAUTH_LOGIN_SUCCESS: usuario='admin' ip='10.0.0.1'\r\nFalso encerramento"
        )
        record.audit = {
            "colaborador": "Carlos Injetor",
            "evidencia": payload_malicioso,
            "motivo": "Linha1\nLinha2\rLinha3",
        }

        formatter = JSONAuditFormatter()
        linha_log = formatter.format(record)

        # Garantia CWE-117: Uma linha de log é SEMPRE rigorosamente uma única linha
        self.assertEqual(linha_log.count("\n"), 0, "Log nunca deve conter quebras de linha cruas (CWE-117).")
        self.assertEqual(linha_log.count("\r"), 0, "Log nunca deve conter retorno de carro cru.")

        # Validação estrutural do JSON
        dados = json.loads(linha_log)
        self.assertEqual(dados["event"], "OFFBOARDING_ITEM_REVOKED")
        self.assertEqual(dados["level"], "WARNING")
        self.assertIn("AUTH_LOGIN_SUCCESS", dados["evidencia"])
        self.assertIn("ts", dados)


class Phase8InfrastructureAndDeployTests(TestCase):
    """
    Testes de Segurança para Fase 8: Infraestrutura & Deploy Seguro.

    Cobre:
    - 8.1: Docker Compose fail-closed sem credenciais e chaves padrão (CIS 3.3)
    - 8.2: Proxy reverso Caddy com terminação TLS e cabeçalho X-Forwarded-Proto condicional
    - 8.3: Allowlist no .dockerignore e exclusão de backups no .gitignore
    - 8.4: Script de backup com criptografia assimétrica de chave pública (age)
    - 8.5: HSTS conservador por padrão (preload e subdomínios desativados)
    - 8.6: .env.example seguro por padrão e Dependabot configurado para GitHub Actions
    """

    def setUp(self):
        self.base_dir = Path(__file__).resolve().parent.parent.parent

    def test_81_docker_compose_fail_closed_sem_senhas_default(self):
        """8.1: docker-compose.yml exige variáveis obrigatórias :? e não possui senhas padrão conhecidas."""
        compose_path = self.base_dir / "docker-compose.yml"
        self.assertTrue(compose_path.exists(), "docker-compose.yml não encontrado na raiz.")

        conteudo = compose_path.read_text(encoding="utf-8")

        # Exige sintaxe fail-closed :?
        self.assertIn("${SECRET_KEY:?", conteudo)
        self.assertIn("${POSTGRES_PASSWORD:?", conteudo)

        # Proíbe senhas padrão antigas no compose
        self.assertNotIn("gatekeeper_secure_password_2026", conteudo)
        self.assertNotIn("generate-a-secure-secret-key-for-production-min-50-chars", conteudo)

    def test_82_proxy_reverso_caddy_e_x_forwarded_proto(self):
        """8.2: Caddyfile configurado para terminação TLS e USE_X_FORWARDED_PROTO condicional."""
        caddyfile_path = self.base_dir / "Caddyfile"
        self.assertTrue(caddyfile_path.exists(), "Caddyfile deve existir na raiz do projeto.")

        caddy_content = caddyfile_path.read_text(encoding="utf-8")
        self.assertIn("reverse_proxy web:8000", caddy_content)
        self.assertIn("Strict-Transport-Security", caddy_content)

        # Valida que o compose isolou o serviço web (expose 8000, sem ports exposta no host)
        compose_content = (self.base_dir / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("caddy:", compose_content)
        self.assertIn('expose:\n      - "8000"', compose_content)

        # Valida configuração do Django no core.settings
        from django.conf import settings

        # Por padrão (sem env), USE_X_FORWARDED_PROTO é False e SECURE_PROXY_SSL_HEADER é None
        self.assertFalse(getattr(settings, "USE_X_FORWARDED_PROTO", False))
        self.assertIsNone(getattr(settings, "SECURE_PROXY_SSL_HEADER", None))

    def test_83_dockerignore_allowlist_e_gitignore_backups(self):
        """8.3: .dockerignore adota allowlist (negação universal *) e .gitignore barra backups/dumps."""
        dockerignore_path = self.base_dir / ".dockerignore"
        self.assertTrue(dockerignore_path.exists())

        di_lines = [
            line.strip()
            for line in dockerignore_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertEqual(di_lines[0], "*", ".dockerignore deve iniciar com negação universal '*'.")
        self.assertTrue(any(line.startswith("!apps/") for line in di_lines))
        self.assertTrue(any(line.startswith("!core/") for line in di_lines))

        # .gitignore
        gitignore_path = self.base_dir / ".gitignore"
        gi_content = gitignore_path.read_text(encoding="utf-8")
        self.assertIn("backups/", gi_content)
        self.assertIn("*.sql.gz", gi_content)
        self.assertIn("*.dump", gi_content)
        self.assertIn("*.age", gi_content)

    def test_84_script_backup_usa_age_chave_publica(self):
        """8.4: backup_db.sh valida chave pública age, opera em pipe e não expõe senhas na linha de comando."""
        script_path = self.base_dir / "scripts" / "backup_db.sh"
        self.assertTrue(script_path.exists())

        script_content = script_path.read_text(encoding="utf-8")
        # Validação da variável obrigatória da chave age
        self.assertIn("BACKUP_AGE_RECIPIENT:?", script_content)
        # Uso do age com chave pública
        self.assertIn("age -r", script_content)
        # Nenhuma senha exposta na CLI do openssl
        self.assertNotIn("-pass pass:", script_content)
        self.assertNotIn("openssl enc", script_content)

    def test_85_hsts_conservador_por_padrao(self):
        """8.5: HSTS preload e subdomínios desativados por padrão para evitar quebra de domínios corporativos."""
        from django.conf import settings

        self.assertFalse(settings.SECURE_HSTS_PRELOAD)
        self.assertFalse(settings.SECURE_HSTS_INCLUDE_SUBDOMAINS)

    def test_86_env_example_e_dependabot_actions(self):
        """8.6: .env.example deixa desativações de cookies comentadas e dependabot monitora github-actions."""
        env_example_path = self.base_dir / ".env.example"
        env_content = env_example_path.read_text(encoding="utf-8")

        # As linhas perigosas devem estar devidamente comentadas (#)
        self.assertIn("# SESSION_COOKIE_SECURE=False", env_content)
        self.assertIn("# CSRF_COOKIE_SECURE=False", env_content)
        self.assertIn("# SECURE_SSL_REDIRECT=False", env_content)

        # Dependabot
        dependabot_path = self.base_dir / ".github" / "dependabot.yml"
        dependabot_content = dependabot_path.read_text(encoding="utf-8")
        self.assertIn("github-actions", dependabot_content)

        # GitHub Actions CI com fixação por SHA
        ci_path = self.base_dir / ".github" / "workflows" / "ci.yml"
        ci_content = ci_path.read_text(encoding="utf-8")
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", ci_content)
        self.assertIn("actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38", ci_content)


class Phase9FrontendCleanupAndRegressionTests(TestCase):
    """
    Testes de Regressão para Fase 9: Front-end, Limpeza & Testes de Regressão (Plano v2).

    Cobre:
    - 9.1: Nenhum style="" ou handler on*= inline em templates e admin (CSP style-src 'self' preservada);
           barras de progresso renderizadas com <progress> nativo; selos do admin por classe CSS.
    - 9.2: Configurações CSP_* legadas removidas; /healthz/ responde antes da validação de host
           e do redirecionamento HTTPS, falha com 503 sem banco e fica oculto no Caddy.
    - Template de PR com checklist de segurança.
    """

    def setUp(self):
        self.base_dir = Path(__file__).resolve().parent.parent.parent

        self.user_auditor = User.objects.create_user(
            username="auditor.fase9", email="auditor.fase9@empresa.com.br", password="ComplexPassword123!"
        )
        self.user_auditor.groups.add(Group.objects.get(name="Auditor"))
        responsavel = User.objects.create_user(
            username="analista.fase9", email="analista.fase9@empresa.com.br", password="ComplexPassword123!"
        )

        depto = Departamento.objects.create(nome="Infraestrutura Fase 9", sigla="INF9")
        cargo = Cargo.objects.create(nome="Analista de Redes", departamento=depto)
        localidade = Localidade.objects.create(nome="Salvador F9", codigo="SSA-09", cidade="Salvador", estado="BA")
        self.colaborador = Colaborador.objects.create(
            nome_completo="Paula Progresso",
            matricula="MAT-F9-01",
            email_corporativo="paula.progresso@empresa.com.br",
            departamento=depto,
            cargo=cargo,
            localidade=localidade,
            data_admissao=timezone.localdate(),
            status=Colaborador.StatusColaborador.ATIVO,
        )
        self.sistema = Sistema.objects.create(
            nome="Firewall Fase 9",
            tipo=Sistema.TipoSistema.NETWORK,
            criticidade=Sistema.Criticidade.CRITICA,
        )
        vinculo = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema,
            identificador_conta="paula.fw",
            concedido_por=responsavel,
        )
        self.processo = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=responsavel,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        )
        ItemChecklistOffboarding.objects.create(processo=self.processo, vinculo_acesso=vinculo)

    # ------------------------------------------------------------------ 9.1
    def test_91_templates_sem_style_nem_handlers_inline(self):
        """9.1 (catraca): nenhum template usa style="" ou on*="" — ambos seriam bloqueados pela CSP."""
        padrao_style = re.compile(r"\sstyle\s*=", re.IGNORECASE)
        padrao_handler = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
        violacoes = []
        for template in (self.base_dir / "templates").rglob("*.html"):
            conteudo = template.read_text(encoding="utf-8")
            if padrao_style.search(conteudo) or padrao_handler.search(conteudo):
                violacoes.append(str(template.relative_to(self.base_dir)))
        self.assertEqual(violacoes, [], "Templates com estilo/JS inline (bloqueados pela CSP)")

    def test_91_paginas_renderizam_progress_nativo_sem_style(self):
        """9.1: as quatro telas com barra de progresso usam <progress> e carregam o CSS único compilado."""
        self.client.force_login(self.user_auditor)
        rotas = [
            reverse("dashboard"),
            reverse("offboarding_list"),
            reverse("offboarding_detail", kwargs={"pk": self.processo.pk}),
            reverse("colaborador_detail", kwargs={"pk": self.colaborador.pk}),
        ]
        for rota in rotas:
            resp = self.client.get(rota)
            self.assertEqual(resp.status_code, 200, rota)
            conteudo = resp.content.decode()
            self.assertIn('<progress class="gk-progress', conteudo, rota)
            self.assertIn('max="100"', conteudo, rota)
            self.assertNotIn("style=", conteudo, rota)
            self.assertIn("css/tailwind.min.", conteudo, rota)

    def test_91_admin_selos_e_progresso_por_classe_css(self):
        """9.1: selos e progresso do admin não geram style="" e o admin carrega css/admin.css."""
        sistema_admin = admin.site._registry[Sistema]
        colaborador_admin = admin.site._registry[Colaborador]
        vinculo_admin = admin.site._registry[VinculoAcesso]
        processo_admin = admin.site._registry[ProcessoOffboarding]

        html_gerado = [
            sistema_admin.exibir_criticidade(self.sistema),
            colaborador_admin.exibir_status(self.colaborador),
            vinculo_admin.exibir_status(VinculoAcesso.objects.first()),
            processo_admin.exibir_status(self.processo),
            processo_admin.exibir_progresso(self.processo),
        ]
        for html in html_gerado:
            self.assertNotIn("style=", html)

        self.assertIn('class="gk-badge gk-badge--vermelho"', html_gerado[0])  # criticidade CRITICA
        self.assertIn('class="gk-badge gk-badge--verde"', html_gerado[1])  # colaborador ATIVO
        self.assertIn('<progress class="gk-admin-progress"', html_gerado[4])

        for model_admin in (sistema_admin, colaborador_admin, vinculo_admin, processo_admin):
            self.assertIn("/static/css/admin.", str(model_admin.media))

    # ------------------------------------------------------------------ 9.2
    def test_92_configuracoes_csp_legadas_removidas(self):
        """9.2: nenhuma configuração CSP_* do django-csp 3.x (sem efeito no 4.x) permanece."""
        legadas = [nome for nome in dir(settings) if nome.startswith("CSP_")]
        self.assertEqual(legadas, [])
        self.assertIn("DIRECTIVES", settings.CONTENT_SECURITY_POLICY)

    @override_settings(ALLOWED_HOSTS=["gatekeeper.empresa.com.br"], SECURE_SSL_REDIRECT=True)
    def test_92_healthz_responde_sem_host_permitido_e_sem_https(self):
        """9.2: /healthz/ responde 200 ao curl interno do container (Host 127.0.0.1, HTTP puro)."""
        resp = self.client.get("/healthz/", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b"ok")
        self.assertEqual(resp["Cache-Control"], "no-store")

        # O desvio vale só para /healthz/: as demais rotas continuam validando o host.
        resp_login = self.client.get("/login/", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(resp_login.status_code, 400)

    def test_92_healthz_falha_com_503_quando_banco_indisponivel(self):
        """9.2: sem banco, /healthz/ responde 503 sem expor detalhes do erro."""
        with mock.patch("apps.governance.middleware.connection") as conexao:
            conexao.ensure_connection.side_effect = OperationalError("senha=segredo host=db")
            with self.assertLogs("gatekeeper.audit", level="ERROR"):
                resp = self.client.get("/healthz/")
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.content, b"unavailable")
        self.assertNotIn(b"segredo", resp.content)

    def test_92_healthz_so_aceita_get_e_head(self):
        """9.2: outros métodos seguem a pilha normal (login obrigatório), sem atalho."""
        resp = self.client.post("/healthz/")
        self.assertNotEqual(resp.status_code, 200)

    def test_92_docker_healthcheck_e_caddy(self):
        """9.2: Dockerfile usa /healthz/, Caddy oculta a rota externamente e espera o web saudável."""
        dockerfile = (self.base_dir / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("http://127.0.0.1:8000/healthz/", dockerfile)
        self.assertNotIn("localhost:8000/login/", dockerfile)

        caddyfile = (self.base_dir / "Caddyfile").read_text(encoding="utf-8")
        self.assertIn("respond @healthz 404", caddyfile)

        compose = (self.base_dir / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("web:\n        condition: service_healthy", compose)

    # ------------------------------------------------------- template de PR
    def test_93_template_pr_com_checklist_de_seguranca(self):
        """Template de PR lembra as regras de negar por padrão a cada mudança."""
        template = self.base_dir / ".github" / "pull_request_template.md"
        self.assertTrue(template.exists())
        conteudo = template.read_text(encoding="utf-8")
        for termo in ("rotas_protegidas", "TRANSICOES_PERMITIDAS", 'extra={"audit"', "style=", ".dockerignore", ":?"):
            self.assertIn(termo, conteudo)


class CSSConsistencyAndAccessibilityTests(TestCase):
    """
    Testes do CSS (fonte única em static/css/input.css, compilada por scripts/build_css.sh).

    Cobre:
    - Todo componente gk-* usado em templates/forms existe no CSS compilado (ou no admin.css).
    - Fonte única: components.css e print.css foram incorporados ao input.css.
    - Acessibilidade: foco visível, prefers-reduced-motion e color-scheme escuro.
    - Cores do tema (theme()) em vez de hex solto no input.css.
    - Build reprodutível: versão fixa, checksum SHA-256, verificação no CI e no pre-commit.

    A verificação de que o tailwind.min.css está atualizado em relação aos templates
    roda no CI e no pre-commit (scripts/build_css.sh --check), pois exige o binário do Tailwind.
    """

    def setUp(self):
        self.base_dir = Path(__file__).resolve().parent.parent.parent
        self.css_dir = self.base_dir / "static" / "css"
        self.compilado = (self.css_dir / "tailwind.min.css").read_text(encoding="utf-8")

    def _classes_gk_usadas(self):
        fontes = list((self.base_dir / "templates").rglob("*.html"))
        fontes.append(self.base_dir / "apps" / "governance" / "forms.py")
        classes = set()
        for fonte in fontes:
            conteudo = fonte.read_text(encoding="utf-8")
            for valor in re.findall(r'class(?:="|": ")([^"]*)"', conteudo):
                classes.update(re.findall(r"(?<![\w-])gk-[a-z0-9-]+", valor))
        return classes

    def test_css_todo_componente_gk_usado_existe(self):
        """Uma classe gk-* usada sem definição no CSS ficaria sem estilo em produção."""
        admin_css = (self.css_dir / "admin.css").read_text(encoding="utf-8")
        usadas = self._classes_gk_usadas()
        self.assertTrue(usadas, "Nenhum componente gk-* encontrado nos templates")
        # A classe pode aparecer seguida de {, ",", ":", ">", espaço etc. (ex.: `.gk-allauth>…`).
        faltando = sorted(
            c
            for c in usadas
            if not re.search(rf"\.{re.escape(c)}(?![\w-])", self.compilado)
            and not re.search(rf"\.{re.escape(c)}(?![\w-])", admin_css)
        )
        self.assertEqual(faltando, [], "Componentes usados nos templates sem definição no CSS compilado")

    def test_css_fonte_unica_sem_arquivos_soltos(self):
        """components.css e print.css foram incorporados ao input.css; templates só carregam o CSS compilado."""
        self.assertFalse((self.css_dir / "components.css").exists())
        self.assertFalse((self.css_dir / "print.css").exists())
        permitidos = {"fonts/fonts.css", "css/tailwind.min.css"}
        for template in (self.base_dir / "templates").rglob("*.html"):
            for href in re.findall(
                r"""<link rel="stylesheet" href="\{% static '([^']+)' %\}">""", template.read_text(encoding="utf-8")
            ):
                self.assertIn(href, permitidos, f"{template.name} carrega CSS fora da fonte única: {href}")
        # Regras de impressão do relatório agora vêm do CSS compilado
        self.assertIn("@media print", self.compilado)
        self.assertIn(".no-print", self.compilado)

    def test_css_acessibilidade(self):
        """Foco visível (WCAG 2.4.7), menos movimento (WCAG 2.3.3) e controles nativos no tema escuro."""
        self.assertIn(":focus-visible", self.compilado)
        self.assertIn("prefers-reduced-motion:reduce", self.compilado)
        self.assertIn("color-scheme:dark", self.compilado)
        self.assertIn("scrollbar-color", self.compilado)  # Firefox
        base = (self.base_dir / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertIn('<html lang="pt-BR" class="gk-dark', base)

    def test_css_progress_com_prefixos_em_regras_separadas(self):
        """Seletores -webkit- e -moz- na mesma lista fazem o navegador descartar a regra inteira."""
        misturados = re.findall(r"[^{}]*-webkit-progress[^{}]*-moz-progress[^{}]*\{", self.compilado)
        misturados += re.findall(r"[^{}]*-moz-progress[^{}]*-webkit-progress[^{}]*\{", self.compilado)
        self.assertEqual(misturados, [])
        self.assertIn(".gk-progress--done::-webkit-progress-value{", self.compilado)
        self.assertIn(".gk-progress--done::-moz-progress-bar{", self.compilado)

    def test_css_cores_do_tema_sem_hex_solto(self):
        """No input.css as cores vêm de theme(...), para não divergirem da paleta do Tailwind."""
        fonte = (self.css_dir / "input.css").read_text(encoding="utf-8")
        sem_comentarios = re.sub(r"/\*.*?\*/", "", fonte, flags=re.S)
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b", sem_comentarios), [])

    def test_css_build_reprodutivel_e_verificado(self):
        """Binário do Tailwind com versão fixa e SHA-256; CI e pre-commit falham com CSS desatualizado."""
        script = (self.base_dir / "scripts" / "build_css.sh").read_text(encoding="utf-8")
        self.assertIn('TAILWIND_VERSION="3.4.17"', script)
        self.assertIn("7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4", script)  # linux-x64
        self.assertIn("checksum SHA-256 do binário não confere", script)

        ci = (self.base_dir / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/build_css.sh --check", ci)

        pre_commit = (self.base_dir / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        self.assertIn("scripts/build_css.sh --check", pre_commit)


class AllauthStylingTests(TestCase):
    """
    Telas do allauth (MFA, códigos de recuperação, reautenticação) com o visual do GateKeeper.

    Regressão do bug em que a tela "Ativar aplicativo autenticador" saía sem estilo:
    - o layout colocava o cartão no bloco `content`, que a página do allauth sobrescrevia;
    - os elementos (`allauth/elements/*.html`) eram o HTML padrão, sem classes.
    """

    SENHA = "Xk9!vQ2#mLp7zRr"

    def setUp(self):
        self.base_dir = Path(__file__).resolve().parent.parent.parent
        self.user = User.objects.create_user("staff.allauth", "staff.allauth@empresa.com.br", self.SENHA, is_staff=True)

    def _login_reautenticado(self):
        self.client.post("/login/", {"login": self.user.username, "password": self.SENHA})
        self.client.post("/accounts/reauthenticate/", {"password": self.SENHA})

    def test_layout_allauth_envolve_content_pelo_bloco_main(self):
        """O cartão fica em `main`; a página do allauth preenche `content` dentro dele."""
        base = (self.base_dir / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertIn("{% block main %}{% block content %}{% endblock %}{% endblock %}", base)
        for layout in ("entrance.html", "manage.html"):
            conteudo = (self.base_dir / "templates" / "allauth" / "layouts" / layout).read_text(encoding="utf-8")
            self.assertIn("{% block main %}", conteudo, layout)
            self.assertIn("{% block content %}{% endblock %}", conteudo, layout)

    def test_tela_ativar_totp_estilizada(self):
        """A tela do print do bug: cartão, título, QR com fundo claro, segredo copiável, campo e botão estilizados."""
        self._login_reautenticado()
        resp = self.client.get(reverse("mfa_activate_totp"))
        self.assertEqual(resp.status_code, 200)
        html = resp.content.decode()
        for esperado in (
            'class="gk-auth-card gk-allauth"',
            'class="gk-h1"',
            'class="gk-text"',
            'class="gk-qr"',
            'class="gk-field-control"',
            'class="gk-btn-primary"',
        ):
            self.assertIn(esperado, html)
        # Segredo sem `name` (não vai no POST): readonly para poder ser copiado
        segredo = re.search(r'<input[^>]*id="authenticator_secret"[^>]*>', html, re.S).group(0)
        self.assertIn("readonly", segredo)
        self.assertNotIn("disabled", segredo)
        self.assertNotIn("style=", html)
        self.assertNotIn("{% comment", html)

    def test_demais_telas_allauth_usam_cartao_e_elementos(self):
        """Telas de gestão de MFA e conta renderizam no cartão, com título e botões do GateKeeper."""
        # TOTP ativado depois do login: antes dele, o login passaria a exigir o código de MFA.
        self._login_reautenticado()
        Authenticator.objects.create(user=self.user, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"})
        for nome in ("mfa_index", "mfa_deactivate_totp", "account_change_password", "account_reauthenticate"):
            resp = self.client.get(reverse(nome))
            self.assertEqual(resp.status_code, 200, nome)
            html = resp.content.decode()
            self.assertIn("gk-auth-card", html, nome)
            self.assertIn('class="gk-h1"', html, nome)
            self.assertIn("gk-btn-", html, nome)
            self.assertNotIn("style=", html, nome)

    def test_variantes_de_botao_pelos_tags_do_allauth(self):
        """danger > link > secundário > primário (sem tags); `tool` usa o tamanho pequeno."""
        from django.template import Context, Origin, Template

        # O allauth usa o nome do template de origem para resolver o elemento.
        origem = Origin(name="teste_botao.html", template_name="teste_botao.html")

        casos = {
            'tags="danger,delete"': "gk-btn-danger",
            'tags="link,cancel"': "gk-btn-link",
            'tags="outline,primary"': "gk-btn-secondary",
            'tags="mfa,authenticator,edit,tool"': "gk-btn-secondary gk-btn-sm",
            'tags="prominent,login"': "gk-btn-primary",
            "": "gk-btn-primary",
        }
        for tags, classe in casos.items():
            html = Template(
                "{% load allauth %}{% element button type='submit' " + tags + " %}OK{% endelement %}",
                origin=origem,
            ).render(Context({}))
            self.assertIn(f'class="{classe}"', html, tags or "(sem tags)")


class Phase10To12IntegrityAndDeployTests(TestCase):
    """
    Testes de integridade, identidade e deploy para as Fases 10, 11 e 12 (Plano v3).
    Cobre os 12 achados da Tabela 12.3:
    10.1 - Admin somente leitura para offboarding e permissões restritas do Analista TI
    10.2 - TOTP tolerância zero padrão (sem replay/reuso após 30s)
    10.3 - Cache compartilhado via dbcache (não LocMemCache/DummyCache)
    10.4 - Rate limiting por IP e por conta (key)
    10.5 - Exigência de MFA por permissão efetiva (além de grupo)
    10.6 - System checks gatekeeper.E001-E004 para deploy
    11.1 - Serviço migrate com createcachetable no compose
    11.2 - HSTS sem includeSubDomains no Caddyfile
    11.3 - Script de backup atômico e sem credenciais na CLI
    11.4 - CSP estrita com base-uri e object-src 'none'
    12.1 - Validação de permissão para 'Não Aplicável' no serviço
    12.2 - Registro de e-mail em logs de falha de login
    """

    def setUp(self):
        self.client = Client()

        self.grupo_analista = Group.objects.get(name="Analista TI")
        self.grupo_gestor = Group.objects.get(name="Gestor SecOps")

        self.user_analista = User.objects.create_user(
            username="analista.p3", email="analista.p3@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.user_analista.groups.add(self.grupo_analista)
        Authenticator.objects.create(
            user=self.user_analista, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        self.user_gestor = User.objects.create_user(
            username="gestor.p3", email="gestor.p3@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.user_gestor.groups.add(self.grupo_gestor)
        Authenticator.objects.create(
            user=self.user_gestor, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        self.superuser = User.objects.create_superuser(
            username="admin.p3", email="admin.p3@empresa.com.br", password="ComplexPassword123!"
        )
        Authenticator.objects.create(
            user=self.superuser, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        # Dados de apoio
        self.loc = Localidade.objects.create(nome="Recife", codigo="PE-REC", cidade="Recife", estado="PE")
        self.dept = Departamento.objects.create(nome="Segurança", sigla="SEC")
        self.cargo = Cargo.objects.create(nome="Engenheiro", departamento=self.dept)
        self.colab = Colaborador.objects.create(
            nome_completo="Lucas Alvo",
            matricula="SEC-0099",
            email_corporativo="lucas@empresa.com.br",
            departamento=self.dept,
            cargo=self.cargo,
            localidade=self.loc,
            data_admissao="2026-01-01",
        )
        self.sis = Sistema.objects.create(
            nome="GitLab Interno", tipo=Sistema.TipoSistema.SAAS, criticidade=Sistema.Criticidade.ALTA
        )
        self.vinculo = VinculoAcesso.objects.create(
            colaborador=self.colab,
            sistema=self.sis,
            identificador_conta="lucas.git",
            status=VinculoAcesso.StatusAcesso.ATIVO,
        )
        self.processo = ProcessoOffboarding.objects.create(
            colaborador=self.colab,
            responsavel_ti=self.user_gestor,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        )
        self.item = ItemChecklistOffboarding.objects.create(
            processo=self.processo,
            vinculo_acesso=self.vinculo,
            status=ItemChecklistOffboarding.StatusItem.PENDENTE,
        )

    def test_101_admin_somente_leitura_offboarding(self):
        """10.1: ProcessoOffboarding e ItemChecklistOffboarding são somente leitura no Django Admin; Analista TI não tem change_*."""
        # 1. Analista TI não tem as permissões de change_ no grupo
        permissoes_analista = set(self.grupo_analista.permissions.values_list("codename", flat=True))
        self.assertNotIn("change_processooffboarding", permissoes_analista)
        self.assertNotIn("change_itemchecklistoffboarding", permissoes_analista)

        # 2. Superuser recebe 403 ao tentar submeter POST de alteração no Admin
        self.client.force_login(self.superuser)
        url_proc = reverse("admin:governance_processooffboarding_change", args=[self.processo.pk])
        resp_proc = self.client.post(url_proc, {"observacoes": "tentativa_edicao_proibida"})
        self.assertEqual(resp_proc.status_code, 403)

        url_item = reverse("admin:governance_itemchecklistoffboarding_change", args=[self.item.pk])
        resp_item = self.client.post(url_item, {"observacao": "tentativa_edicao_proibida"})
        self.assertEqual(resp_item.status_code, 403)

        # 3. Em VinculoAcessoAdmin, campos de auditoria são readonly_fields
        from apps.governance.admin import VinculoAcessoAdmin

        vinculo_admin = VinculoAcessoAdmin(VinculoAcesso, admin.site)
        readonly = vinculo_admin.get_readonly_fields(mock.MagicMock())
        for campo in ("concedido_por", "revogado_por", "data_concessao", "data_revogacao"):
            self.assertIn(campo, readonly)

    def test_102_totp_sem_reuso_tolerancia_zero(self):
        """10.2: MFA_TOTP_TOLERANCE padrão 0 rejeita reuso após a janela de 30s (+35s e +65s)."""
        from allauth.mfa.totp.internal import auth as totp_auth

        self.assertEqual(settings.MFA_TOTP_TOLERANCE, 0)

        secret = totp_auth.generate_totp_secret()
        t0 = 1700000000.0  # Unix timestamp de referência

        with mock.patch("time.time", return_value=t0):
            counters = list(totp_auth.yield_hotp_counters_from_time())
            code = totp_auth.format_hotp_value(totp_auth.hotp_value(secret, counters[0]))
            valido_t0 = totp_auth.validate_totp_code(secret, code)
            self.assertTrue(valido_t0, "Código deve ser válido no momento da emissão (t0)")

        with mock.patch("time.time", return_value=t0 + 35):
            valido_t35 = totp_auth.validate_totp_code(secret, code)
            self.assertFalse(valido_t35, "Código não deve ser aceito na janela seguinte (+35s) com tolerância 0")

        with mock.patch("time.time", return_value=t0 + 65):
            valido_t65 = totp_auth.validate_totp_code(secret, code)
            self.assertFalse(valido_t65, "Código não deve ser aceito duas janelas depois (+65s)")

    def test_103_cache_compartilhado_dbcache(self):
        """10.3: Backend de cache padrão é DatabaseCache compartilhado, não LocMemCache ou DummyCache."""
        backend = settings.CACHES["default"]["BACKEND"]
        self.assertNotIn("LocMemCache", backend)
        self.assertNotIn("DummyCache", backend)
        self.assertIn("DatabaseCache", backend)

    def test_104_rate_limit_por_ip_e_chave(self):
        """10.4: Rate limit de login_failed protege tanto por IP quanto por conta (key)."""
        import allauth.core.ratelimit as rl

        cfg = settings.ACCOUNT_RATE_LIMITS.get("login_failed", "")
        rates = rl._impl.parse_rates(cfg)
        self.assertTrue(
            any(r.per == "key" for r in rates), "ACCOUNT_RATE_LIMITS['login_failed'] deve conter limite por key"
        )
        self.assertTrue(
            any(r.per == "ip" for r in rates), "ACCOUNT_RATE_LIMITS['login_failed'] deve conter limite por ip"
        )

    def test_105_mfa_exigido_por_permissao_efetiva(self):
        """10.5: Usuário sem grupo mas com permissão de escrita direta é obrigado a cadastrar TOTP."""
        from apps.governance.middleware import exige_mfa

        user_direto = User.objects.create_user(
            username="sem.grupo", email="sem.grupo@empresa.com.br", password="ComplexPassword123!"
        )
        # Inicialmente sem permissões de escrita -> não exige MFA
        self.assertFalse(exige_mfa(user_direto))

        # Adiciona permissão de escrita direta
        perm = Permission.objects.get(codename="revogar_item_offboarding")
        user_direto.user_permissions.add(perm)
        user_direto = User.objects.get(pk=user_direto.pk)  # recarrega permissões

        self.assertTrue(exige_mfa(user_direto))

        # Ao acessar o sistema autenticado e sem TOTP, deve ser redirecionado para ativação de TOTP
        self.client.force_login(user_direto)
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("mfa_activate_totp"), resp.headers["Location"])

    def test_106_system_checks_bloqueiam_configuracoes_inseguras(self):
        """10.6: System checks gatekeeper.E001-E004 barram regressões de segurança com DEBUG=False."""
        from apps.governance.checks import run_gatekeeper_deploy_checks

        # 1. Configuração padrão deve passar sem erros
        with override_settings(DEBUG=False):
            erros = run_gatekeeper_deploy_checks()
            self.assertEqual(erros, [])

        # 2. MFA_TOTP_TOLERANCE > 0 -> gatekeeper.E001
        with override_settings(DEBUG=False, MFA_TOTP_TOLERANCE=1):
            erros = run_gatekeeper_deploy_checks()
            self.assertTrue(any(e.id == "gatekeeper.E001" for e in erros))

        # 3. LocMemCache -> gatekeeper.E002
        with override_settings(
            DEBUG=False, CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
        ):
            erros = run_gatekeeper_deploy_checks()
            self.assertTrue(any(e.id == "gatekeeper.E002" for e in erros))

        # 4. login_failed sem 'key' -> gatekeeper.E003
        with override_settings(DEBUG=False, ACCOUNT_RATE_LIMITS={"login_failed": "10/m/ip"}):
            erros = run_gatekeeper_deploy_checks()
            self.assertTrue(any(e.id == "gatekeeper.E003" for e in erros))

        # 5. MFA_TOTP_INSECURE_BYPASS_CODE ativo com DEBUG=False -> gatekeeper.E004
        with override_settings(DEBUG=False, MFA_TOTP_INSECURE_BYPASS_CODE="000000"):
            erros = run_gatekeeper_deploy_checks()
            self.assertTrue(any(e.id == "gatekeeper.E004" for e in erros))

    def test_111_compose_contem_servico_migrate_com_createcachetable(self):
        """11.1: docker-compose.yml possui serviço migrate com createcachetable e web depende de sua conclusão."""
        compose_path = Path(settings.BASE_DIR) / "docker-compose.yml"
        self.assertTrue(compose_path.exists())
        conteudo = compose_path.read_text(encoding="utf-8")

        self.assertIn("migrate:", conteudo)
        self.assertIn("python manage.py migrate --noinput && python manage.py createcachetable", conteudo)
        self.assertIn("condition: service_completed_successfully", conteudo)

    def test_112_caddyfile_sem_includesubdomains(self):
        """11.2: Caddyfile não contém includeSubDomains no cabeçalho Strict-Transport-Security."""
        caddy_path = Path(settings.BASE_DIR) / "Caddyfile"
        self.assertTrue(caddy_path.exists())
        conteudo = caddy_path.read_text(encoding="utf-8")

        self.assertNotIn("includeSubDomains", conteudo)
        self.assertIn('Strict-Transport-Security "max-age=31536000"', conteudo)

    def test_113_script_backup_atomico_e_sem_senha_cli(self):
        """11.3: scripts/backup_db.sh não passa DATABASE_URL ao pg_dump e utiliza arquivo .partial com trap."""
        script_path = Path(settings.BASE_DIR) / "scripts" / "backup_db.sh"
        self.assertTrue(script_path.exists())
        conteudo = script_path.read_text(encoding="utf-8")

        self.assertNotIn('pg_dump --format=custom "${DATABASE_URL}"', conteudo)
        self.assertIn("pg_dump --format=custom", conteudo)
        self.assertIn('PARTIAL_FILE="${FINAL_FILE}.partial"', conteudo)
        self.assertIn("trap 'rm -f \"${PARTIAL_FILE}\"' EXIT", conteudo)
        self.assertIn('mv "${PARTIAL_FILE}" "${FINAL_FILE}"', conteudo)

    def test_114_csp_contem_base_uri_e_object_src_none(self):
        """11.4: CSP possui diretivas base-uri 'none' e object-src 'none' em settings e nos headers."""
        directives = settings.CONTENT_SECURITY_POLICY["DIRECTIVES"]
        self.assertEqual(directives.get("base-uri"), ["'none'"])
        self.assertEqual(directives.get("object-src"), ["'none'"])

        resp = self.client.get("/login/")
        csp_header = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("base-uri 'none'", csp_header)
        self.assertIn("object-src 'none'", csp_header)

    def test_121_servico_revogar_nao_aplicavel_exige_permissao(self):
        """12.1: revogar_item_checklist levanta PermissionDenied se o responsável não tiver governance.marcar_nao_aplicavel."""
        # Analista TI NÃO possui 'marcar_nao_aplicavel'
        with self.assertRaises(PermissionDenied):
            revogar_item_checklist(
                item_id=self.item.pk,
                responsavel=self.user_analista,
                evidencia="",
                observacao="Justificativa longa e detalhada com mais de 20 caracteres para teste",
                status=ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL,
            )

        # Gestor SecOps POSSUI 'marcar_nao_aplicavel' -> Deve executar com sucesso
        item_atualizado, proc_atualizado = revogar_item_checklist(
            item_id=self.item.pk,
            responsavel=self.user_gestor,
            evidencia="",
            observacao="Justificativa longa e detalhada com mais de 20 caracteres para teste",
            status=ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL,
        )
        self.assertEqual(item_atualizado.status, ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL)
        self.assertEqual(item_atualizado.vinculo_acesso.status, VinculoAcesso.StatusAcesso.REVOGADO)

    def test_122_log_falha_login_identifica_email(self):
        """12.2: Tentativa de login malsucedida usando e-mail registra o e-mail nos logs de auditoria SOC."""
        with self.assertLogs("gatekeeper.audit", level="WARNING") as cm:
            user_login_failed.send(
                sender=self.__class__,
                credentials={"email": "alvo.investigado@empresa.com.br"},
                request=None,
            )
        self.assertTrue(
            any(
                getattr(rec, "audit", {}).get("tentativa_usuario") == "alvo.investigado@empresa.com.br"
                for rec in cm.records
            ),
            f"E-mail não encontrado nos records capturados: {[getattr(r, 'audit', {}) for r in cm.records]}",
        )


class RevisaoPosPlanoV3Tests(TestCase):
    """
    Regressões encontradas na revisão de segurança após o Plano v3:
    R1 - `migrate` sozinho cria a tabela do cache (dbcache), sem depender do compose
    R2 - Produção roda `check --deploy` antes de migrar (configuração insegura impede a subida)
    R3 - Vínculo revogado é somente leitura no Admin (não pode ser reativado à mão)
    R4 - Tela de histórico do simple_history não grava (revert exigia só permissão de leitura)
    """

    def setUp(self):
        Phase10To12IntegrityAndDeployTests.setUp(self)
        self.user_auditor = User.objects.create_user(
            username="auditor.rev", email="auditor.rev@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.user_auditor.groups.add(Group.objects.get(name="Auditor"))
        Authenticator.objects.create(
            user=self.user_auditor, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

    def test_r1_migrate_cria_tabela_de_cache(self):
        """R1: a migração recria a tabela do DatabaseCache quando ela não existe."""
        import importlib

        from django.core.cache import cache
        from django.db import connection

        tabela = settings.CACHES["default"]["LOCATION"]
        with connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE {connection.ops.quote_name(tabela)}")  # nosec B608 - nome vem do settings
        self.assertNotIn(tabela, connection.introspection.table_names())

        migracao = importlib.import_module("apps.governance.migrations.0007_criar_tabela_cache")
        migracao.criar_tabela_cache(None, connection.schema_editor())

        self.assertIn(tabela, connection.introspection.table_names())
        cache.set("gk-r1", "ok")
        self.assertEqual(cache.get("gk-r1"), "ok")

    def test_r2_compose_roda_check_deploy_antes_do_migrate(self):
        """R2: o serviço migrate falha (e o web não sobe) se o check --deploy acusar erro."""
        conteudo = (Path(settings.BASE_DIR) / "docker-compose.yml").read_text(encoding="utf-8")
        comando = "python manage.py check --deploy --fail-level ERROR && python manage.py migrate --noinput"
        self.assertIn(comando, conteudo)

    def test_r3_vinculo_revogado_e_somente_leitura_no_admin(self):
        """R3: nem superusuário reativa no Admin um acesso já revogado; vínculo ativo segue editável."""
        from apps.governance.admin import VinculoAcessoAdmin

        vinculo_admin = VinculoAcessoAdmin(VinculoAcesso, admin.site)
        request = mock.MagicMock(user=self.superuser)
        self.assertTrue(vinculo_admin.has_change_permission(request, self.vinculo))

        self.vinculo.status = VinculoAcesso.StatusAcesso.REVOGADO
        self.vinculo.save()
        self.assertFalse(vinculo_admin.has_change_permission(request, self.vinculo))

        self.client.force_login(self.superuser)
        url = reverse("admin:governance_vinculoacesso_change", args=[self.vinculo.pk])
        resp = self.client.post(url, {"status": VinculoAcesso.StatusAcesso.ATIVO})
        self.assertEqual(resp.status_code, 403)
        self.vinculo.refresh_from_db()
        self.assertEqual(self.vinculo.status, VinculoAcesso.StatusAcesso.REVOGADO)

        # O inline na tela do colaborador não pode ser um caminho alternativo de edição/concessão
        from apps.governance.admin import VinculoAcessoInline

        inline = VinculoAcessoInline(Colaborador, admin.site)
        self.assertFalse(inline.has_add_permission(request, self.colab))
        self.assertFalse(inline.has_change_permission(request, self.colab))
        self.assertFalse(inline.has_delete_permission(request, self.colab))

    def test_r4_historico_do_admin_nao_permite_gravar(self):
        """R4: POST na tela de versão do histórico é negado, inclusive para quem só tem leitura."""
        from simple_history.admin import SimpleHistoryAdmin

        from apps.governance.admin import HistoricoSomenteLeituraAdmin

        # Todo admin com histórico usa a base segura (protege admins futuros também)
        for model_admin in admin.site._registry.values():
            if isinstance(model_admin, SimpleHistoryAdmin):
                self.assertIsInstance(model_admin, HistoricoSomenteLeituraAdmin, type(model_admin).__name__)

        versao = self.processo.history.earliest()
        url = reverse("admin:governance_processooffboarding_simple_history", args=[self.processo.pk, versao.history_id])
        dados = {
            "colaborador": self.colab.pk,
            "status": ProcessoOffboarding.StatusOffboarding.CONCLUIDO,
            "responsavel_ti": self.user_gestor.pk,
            "observacoes": "alterado pelo historico",
        }
        for usuario in (self.user_auditor, self.superuser):
            with self.subTest(usuario=usuario.username):
                self.client.force_login(usuario)
                self.assertEqual(self.client.get(url).status_code, 200)  # consultar continua permitido
                self.assertEqual(self.client.post(url, dados).status_code, 403)
                self.processo.refresh_from_db()
                self.assertEqual(self.processo.status, ProcessoOffboarding.StatusOffboarding.INICIADO)
