"""
Testes do módulo de Governança & IAM - GateKeeper-DBF.
"""

from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.governance.forms import RevogacaoItemForm
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
from apps.governance.services import iniciar_offboarding, revogar_item_checklist

User = get_user_model()


class OffboardingIntegridadeServicoTests(TestCase):
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


class OffboardingDevSecOpsPerformanceTests(TestCase):
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


class OffboardingMaquinaEstadosTests(TestCase):
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


class OffboardingRegrasNegocioTests(TestCase):
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
