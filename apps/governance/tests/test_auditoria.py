"""
Testes do módulo de Governança & IAM - GateKeeper-DBF.
"""

import json
import logging

from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.signals import user_login_failed
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.governance.logging import JSONAuditFormatter
from apps.governance.models import (
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
from apps.governance.utils import get_client_ip

User = get_user_model()


class AuditoriaXSSStoredTests(TestCase):
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


class AuditoriaSOCSinaisTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="soc.auditor", email="soc@empresa.com.br", password="ComplexPassword123!"
        )
        grupo_auditor = Group.objects.get(name="Auditor")
        self.user.groups.add(grupo_auditor)

    def test_23_trilha_auditoria_soc_sinais(self):
        """2.4 / 7.2: Eventos de autenticação disparam logs estruturados em JSON para ingestão em SIEM."""
        from apps.governance.logging import JSONAuditFormatter

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


class AuditoriaIPETelemetriaTests(TestCase):
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


class AuditoriaFalhaLoginEmailTests(TestCase):
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
