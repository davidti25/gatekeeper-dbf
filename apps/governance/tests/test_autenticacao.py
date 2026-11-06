"""
Testes do módulo de Governança & IAM - GateKeeper-DBF.
"""

from unittest import mock

from allauth.mfa.models import Authenticator
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

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

User = get_user_model()


class AutenticacaoBasicaTests(TestCase):
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


class SessaoECookiesTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="soc.auditor", email="soc@empresa.com.br", password="ComplexPassword123!"
        )
        grupo_auditor = Group.objects.get(name="Auditor")
        self.user.groups.add(grupo_auditor)

    def test_22_sessao_e_hardening_cookies(self):
        """2.4: Validação de cookies de sessão de 8 horas e isolamento HttpOnly."""
        from django.conf import settings

        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)
        self.assertEqual(settings.SESSION_COOKIE_AGE, 28800)
        self.assertTrue(settings.SESSION_EXPIRE_AT_BROWSER_CLOSE)
        self.assertEqual(settings.X_FRAME_OPTIONS, "DENY")
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)


class MFAIdentidadeForteTests(TestCase):
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


class ProtecaoEntradaAuthTests(TestCase):
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


class AutenticacaoIntegridadeTests(TestCase):
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
