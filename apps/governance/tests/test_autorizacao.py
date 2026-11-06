"""
Testes do módulo de Governança & IAM - GateKeeper-DBF.
"""

from allauth.mfa.models import Authenticator
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.governance import urls as gov_urls
from apps.governance.models import (
    CampanhaRevisao,
    Cargo,
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    ItemRevisao,
    Localidade,
    PerfilAcesso,
    ProcessoOffboarding,
    Sistema,
    VinculoAcesso,
)
from apps.governance.tests.base import (
    setup_fase10_fixtures,
)

User = get_user_model()


class AutorizacaoRBACBasicaTests(TestCase):
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


class CatracaERotasProtegidasTests(TestCase):
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
        self.campanha = CampanhaRevisao.objects.create(
            nome="Campanha Catraca",
            prazo=timezone.localdate() + timezone.timedelta(days=15),
            criada_por=self.user_analista,
            status=CampanhaRevisao.StatusCampanha.ABERTA,
        )
        self.item_revisao = ItemRevisao.objects.create(
            campanha=self.campanha,
            vinculo=self.vinculo,
            revisor=self.user_analista,
            decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
        )

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
            "campanha_list": {},
            "abrir_campanha": {},
            "campanha_painel": {"pk": self.campanha.pk},
            "encerrar_campanha": {"pk": self.campanha.pk},
            "campanha_relatorio": {"pk": self.campanha.pk},
            "executar_revogacao_revisao": {"pk": self.campanha.pk, "item_id": self.item_revisao.pk},
            "minhas_revisoes": {},
            "decidir_revisao": {"item_id": self.item_revisao.pk},
            "decidir_revisao_lote": {},
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


class MatrizAutorizacaoTests(TestCase):
    ROTAS_ESCRITA = {
        "iniciar_offboarding": "governance.iniciar_offboarding",
        "revogar_item_offboarding": "governance.revogar_item_offboarding",
        "abrir_campanha": "governance.abrir_campanha_revisao",
        "encerrar_campanha": "governance.abrir_campanha_revisao",
        "decidir_revisao": "governance.revisar_acesso",
        "decidir_revisao_lote": "governance.revisar_acesso",
        "executar_revogacao_revisao": "governance.revogar_item_offboarding",
    }
    SOMENTE_LEITURA_NO_ADMIN = {
        "governance.ProcessoOffboarding",
        "governance.ItemChecklistOffboarding",
        "governance.CampanhaRevisao",
        "governance.ItemRevisao",
    }

    def setUp(self):
        setup_fase10_fixtures(self)
        PerfilAcesso.objects.create(sistema=self.sis, nome="Desenvolvedor")
        self.perfis = {
            "Auditor": self._usuario_staff("auditor.matriz", "Auditor"),
            "Analista TI": self._usuario_staff("analista.matriz", "Analista TI"),
            "Gestor SecOps": self._usuario_staff("gestor.matriz", "Gestor SecOps"),
        }

    def _usuario_staff(self, username, grupo):
        user = User.objects.create_user(
            username=username, email=f"{username}@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        user.groups.add(Group.objects.get(name=grupo))
        # Com TOTP cadastrado, o RequireMFAMiddleware não redireciona e o teste atinge a camada de permissão
        Authenticator.objects.create(user=user, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"})
        return User.objects.get(pk=user.pk)  # recarrega para não usar cache de permissões

    def _estado_do_banco(self):
        from django.apps import apps

        modelos = set(admin.site._registry) | set(apps.get_app_config("governance").get_models())
        estado = {m._meta.label: list(m._default_manager.order_by("pk").values()) for m in modelos}
        for linha in estado["auth.User"]:
            linha.pop("last_login")  # muda a cada force_login; não é gravação feita pela tela testada
        return estado

    def _post_negado(self, user, url, dados, contexto):
        self.client.force_login(user)
        antes = self._estado_do_banco()
        resp = self.client.post(url, dados)
        self.assertEqual(resp.status_code, 403, f"{contexto}: esperado 403, recebeu {resp.status_code}")
        self.assertEqual(antes, self._estado_do_banco(), f"{contexto}: o banco foi alterado apesar do 403")

    def test_admin_nega_gravacao_sem_permissao_em_todos_os_modelos(self):
        """Para cada modelo do admin, perfil e ação (add/change/delete): sem a permissão Django -> 403 e banco intacto."""
        from django.contrib.auth import get_permission_codename

        combinacoes_testadas = 0
        for model in admin.site._registry:
            opts = model._meta
            obj = model._default_manager.first()
            if opts.app_label == "governance":
                self.assertIsNotNone(obj, f"Crie uma instância de {opts.label} no setUp para testar change/delete")
            acoes = [("add", reverse(f"admin:{opts.app_label}_{opts.model_name}_add"), {})]
            if obj is not None:
                acoes += [
                    ("change", reverse(f"admin:{opts.app_label}_{opts.model_name}_change", args=[obj.pk]), {}),
                    (
                        "delete",
                        reverse(f"admin:{opts.app_label}_{opts.model_name}_delete", args=[obj.pk]),
                        {"post": "yes"},
                    ),
                ]
            for nome_perfil, user in self.perfis.items():
                for acao, url, dados in acoes:
                    if user.has_perm(f"{opts.app_label}.{get_permission_codename(acao, opts)}"):
                        continue  # permitido por desenho; regras extras ficam nos testes específicos
                    with self.subTest(modelo=opts.label, perfil=nome_perfil, acao=acao):
                        self._post_negado(user, url, dados, f"{nome_perfil} {acao} {opts.label}")
                        combinacoes_testadas += 1

        # Sanidade: a matriz realmente exercitou casos (inclui tentativa de escalar privilégio em auth.User/Group)
        self.assertGreater(combinacoes_testadas, 50)

        # Controle positivo: com permissão, a requisição passa da camada de autorização (não é 403 por outro motivo)
        self.client.force_login(self.perfis["Gestor SecOps"])
        url = reverse("admin:governance_colaborador_change", args=[self.colab.pk])
        self.assertEqual(self.client.get(url).status_code, 200)

    def test_admin_offboarding_somente_leitura_para_todos(self):
        """Processo e checklist de offboarding: add/change/delete negados a todos os perfis e ao superusuário."""
        from django.apps import apps

        usuarios = {**self.perfis, "superusuário": self.superuser}
        for label in self.SOMENTE_LEITURA_NO_ADMIN:
            model = apps.get_model(label)
            opts = model._meta
            obj = model._default_manager.first()
            acoes = [
                ("add", reverse(f"admin:{opts.app_label}_{opts.model_name}_add"), {}),
                ("change", reverse(f"admin:{opts.app_label}_{opts.model_name}_change", args=[obj.pk]), {}),
                ("delete", reverse(f"admin:{opts.app_label}_{opts.model_name}_delete", args=[obj.pk]), {"post": "yes"}),
            ]
            for nome, user in usuarios.items():
                for acao, url, dados in acoes:
                    with self.subTest(modelo=label, usuario=nome, acao=acao):
                        self._post_negado(user, url, dados, f"{nome} {acao} {label}")

    def test_historico_do_admin_nega_gravacao_em_todos_os_modelos(self):
        """Tela de versão do histórico: POST negado em todo admin com histórico, para todos os perfis e o superusuário."""
        from simple_history.admin import SimpleHistoryAdmin

        usuarios = {**self.perfis, "superusuário": self.superuser}
        modelos_com_historico = 0
        for model, model_admin in admin.site._registry.items():
            if not isinstance(model_admin, SimpleHistoryAdmin):
                continue
            modelos_com_historico += 1
            opts = model._meta
            obj = model._default_manager.first()
            versao = obj.history.earliest()
            url = reverse(f"admin:{opts.app_label}_{opts.model_name}_simple_history", args=[obj.pk, versao.history_id])
            for nome, user in usuarios.items():
                with self.subTest(modelo=opts.label, usuario=nome):
                    self._post_negado(user, url, {}, f"{nome} reverter histórico de {opts.label}")
        self.assertEqual(modelos_com_historico, 7)

    def test_aplicacao_escrita_exige_permissao_e_leitura_recusa_post(self):
        """Telas de escrita: sem a permissão específica -> 403 e banco intacto. Telas de leitura: POST recusado (405)."""
        kwargs_por_rota = {
            "dashboard": {},
            "colaborador_list": {},
            "colaborador_detail": {"pk": self.colab.pk},
            "iniciar_offboarding": {"pk": self.colab.pk},
            "sistema_list": {},
            "matriz_acesso": {},
            "offboarding_list": {},
            "offboarding_detail": {"pk": self.processo.pk},
            "revogar_item_offboarding": {"pk": self.processo.pk, "item_id": self.item.pk},
            "offboarding_relatorio": {"pk": self.processo.pk},
            "campanha_list": {},
            "abrir_campanha": {},
            "campanha_painel": {"pk": self.campanha.pk},
            "encerrar_campanha": {"pk": self.campanha.pk},
            "campanha_relatorio": {"pk": self.campanha.pk},
            "executar_revogacao_revisao": {"pk": self.campanha.pk, "item_id": self.item_revisao.pk},
            "minhas_revisoes": {},
            "decidir_revisao": {"item_id": self.item_revisao.pk},
            "decidir_revisao_lote": {},
        }
        self.assertEqual(
            {p.name for p in gov_urls.urlpatterns},
            set(kwargs_por_rota),
            "Rota nova em governance/urls.py: registre-a aqui e, se gravar dados, em ROTAS_ESCRITA",
        )
        dados_revogacao = {
            "status": ItemChecklistOffboarding.StatusItem.REVOGADO,
            "evidencia_revogacao": "Conta desativada no console; chamado INC-2026-0042 anexado.",
        }

        # 1. Escrita sem a permissão específica -> 403, para cada perfil
        for nome_rota, perm in self.ROTAS_ESCRITA.items():
            url = reverse(nome_rota, kwargs=kwargs_por_rota[nome_rota])
            for nome_perfil, user in self.perfis.items():
                if user.has_perm(perm):
                    continue
                with self.subTest(rota=nome_rota, perfil=nome_perfil):
                    self._post_negado(user, url, dados_revogacao, f"{nome_perfil} POST {nome_rota}")

        # 2. Leitura nunca aceita POST, nem do perfil com mais permissões
        gestor = self.perfis["Gestor SecOps"]
        self.client.force_login(gestor)
        for nome_rota, kwargs in kwargs_por_rota.items():
            if nome_rota in self.ROTAS_ESCRITA:
                continue
            with self.subTest(rota_leitura=nome_rota):
                antes = self._estado_do_banco()
                resp = self.client.post(reverse(nome_rota, kwargs=kwargs), {})
                self.assertEqual(resp.status_code, 405, f"Rota de leitura '{nome_rota}' aceitou POST")
                self.assertEqual(antes, self._estado_do_banco())

        # 3. "Não Aplicável" exige permissão própria, mesmo para quem pode revogar (Analista TI)
        analista = self.perfis["Analista TI"]
        self.assertTrue(analista.has_perm("governance.revogar_item_offboarding"))
        self.assertFalse(analista.has_perm("governance.marcar_nao_aplicavel"))
        self.client.force_login(analista)
        url_revogar = reverse("revogar_item_offboarding", kwargs=kwargs_por_rota["revogar_item_offboarding"])
        self.client.post(
            url_revogar,
            {
                "status": ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL,
                "observacao": "Sistema descontinuado antes do desligamento do colaborador.",
            },
        )
        self.item.refresh_from_db()
        self.assertEqual(self.item.status, ItemChecklistOffboarding.StatusItem.PENDENTE)

        # 4. Controle positivo: com a permissão, a revogação é gravada e o responsável é quem fez a requisição
        self.client.post(url_revogar, dados_revogacao)
        self.item.refresh_from_db()
        self.assertEqual(self.item.status, ItemChecklistOffboarding.StatusItem.REVOGADO)
        self.assertEqual(self.item.responsavel_revogacao, analista)
