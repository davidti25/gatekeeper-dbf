"""
Testes do módulo de Governança & IAM - GateKeeper-DBF.
"""

from unittest import mock

from allauth.mfa.models import Authenticator
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db.models import ProtectedError
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.governance.models import (
    Cargo,
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    Localidade,
    ProcessoOffboarding,
    Sistema,
    VinculoAcesso,
)
from apps.governance.tests.base import (
    setup_fase10_fixtures,
)

User = get_user_model()


class AdminIntegridadeEHistoricoTests(TestCase):
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


class AdminSomenteLeituraOffboardingTests(TestCase):
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


class AdminImutabilidadeHistoricoTests(TestCase):
    def setUp(self):
        setup_fase10_fixtures(self)
        self.user_auditor = User.objects.create_user(
            username="auditor.rev", email="auditor.rev@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.user_auditor.groups.add(Group.objects.get(name="Auditor"))
        Authenticator.objects.create(
            user=self.user_auditor, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

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
