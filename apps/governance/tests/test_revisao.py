"""
Testes de Regressão da Fase 15: Revisão Periódica de Acessos (Recertificação).

Contempla as 10 regras de segurança da Tabela 15.8 do Plano de Ação v4:
1. Fotografia: Vínculo concedido após a abertura não entra na campanha
2. Revisor: Ordem gestor -> dono -> Gestor SecOps; item sem revisor gera alerta
3. Segregação: Ninguém revisa o próprio acesso (abertura e decisão)
4. Objeto (IDOR): Revisor A recebe 404 ao abrir/decidir item do revisor B
5. Estado: Não decide em campanha ENCERRADA; ENCERRADA não reabre
6. Justificativa: REVOGAR e MANTER-em-CRÍTICO sem justificativa são recusados
7. Lote: Lote recusado se incluir item ALTA/CRÍTICA
8. Revogação: REVOGAR gera tarefa para a TI; acesso só muda com evidência
9. Desligamento: Offboarding desativa o usuário vinculado ao colaborador
10. Auditoria: REVIEW_DECISION emitido com revisor, item e decisão
"""

from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.governance.models import (
    CampanhaRevisao,
    Colaborador,
    ItemRevisao,
    Sistema,
    VinculoAcesso,
)
from apps.governance.services import (
    abrir_campanha,
    determinar_revisor,
    encerrar_campanha,
    executar_revogacao_revisao,
    iniciar_offboarding,
    registrar_decisao,
    registrar_decisao_lote,
)
from apps.governance.tests.base import (
    setup_fase10_fixtures,
)

User = get_user_model()


class RevisaoPeriodicaAcessosTests(TestCase):
    def setUp(self):
        setup_fase10_fixtures(self)

        self.grupo_revisor, _ = Group.objects.get_or_create(name="Revisor")

        # Usuários e revisores adicionais com TOTP para testes de permissão e IDOR
        self.revisor_a = User.objects.create_user(
            username="revisor.alpha", email="alpha@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.revisor_a.groups.add(self.grupo_revisor)
        Authenticator.objects.create(
            user=self.revisor_a, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        self.revisor_b = User.objects.create_user(
            username="revisor.bravo", email="bravo@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.revisor_b.groups.add(self.grupo_revisor)
        Authenticator.objects.create(
            user=self.revisor_b, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        # Usuário associado ao colaborador alvo
        self.user_colab = User.objects.create_user(
            username="lucas.alvo", email="lucas@empresa.com.br", password="ComplexPassword123!"
        )
        self.colab.usuario = self.user_colab
        self.colab.save()

        # Sistemas de diferentes criticidades
        self.sis_critico = Sistema.objects.create(
            nome="AWS Cloud Production",
            tipo=Sistema.TipoSistema.SAAS,
            criticidade=Sistema.Criticidade.CRITICA,
            gestor_responsavel="SecOps Cloud",
        )
        self.sis_medio = Sistema.objects.create(
            nome="Jira Corporativo",
            tipo=Sistema.TipoSistema.SAAS,
            criticidade=Sistema.Criticidade.MEDIA,
            gestor_responsavel="PMO",
        )
        self.sis_baixo = Sistema.objects.create(
            nome="Wiki Confluence",
            tipo=Sistema.TipoSistema.SAAS,
            criticidade=Sistema.Criticidade.BAIXA,
            gestor_responsavel="Suporte",
        )

    def test_15_1_fotografia_ignora_vinculos_concedidos_apos_abertura(self):
        """15.8 (Fotografia): Vínculo concedido após a abertura da campanha não entra na fotografia auditável."""
        prazo = timezone.localdate() + timezone.timedelta(days=15)
        campanha = abrir_campanha(
            nome="Campanha Fotografia Q4",
            prazo=prazo,
            criada_por=self.user_gestor,
        )

        itens_iniciais = list(campanha.itens.values_list("vinculo_id", flat=True))
        self.assertIn(self.vinculo.id, itens_iniciais)

        # Cria novo vínculo concedido DEPOIS da abertura
        novo_vinculo = VinculoAcesso.objects.create(
            colaborador=self.colab,
            sistema=self.sis_medio,
            identificador_conta="lucas.jira",
            status=VinculoAcesso.StatusAcesso.ATIVO,
        )

        # O novo vínculo não pode pertencer à campanha já aberta
        self.assertFalse(campanha.itens.filter(vinculo=novo_vinculo).exists())

    def test_15_2_ordem_de_revisor_e_alerta_para_item_sem_revisor(self):
        """15.8 (Revisor): Ordem gestor -> dono -> Gestor SecOps; ausência gera log de alerta."""
        # 1. Gestor Imediato com usuário ativo
        gestor_colab = Colaborador.objects.create(
            nome_completo="Gestor Chefe",
            matricula="SEC-0001",
            email_corporativo="chefe@empresa.com.br",
            departamento=self.dept,
            cargo=self.cargo,
            localidade=self.loc,
            data_admissao="2020-01-01",
            usuario=self.revisor_a,
        )
        self.colab.gestor_imediato = gestor_colab
        self.colab.save()

        rev = determinar_revisor(self.vinculo)
        self.assertEqual(rev, self.revisor_a)

        # 2. Gestor sem usuário -> Recai no dono do sistema
        gestor_colab.usuario = None
        gestor_colab.save()
        self.sis.dono = self.revisor_b
        self.sis.save()

        rev = determinar_revisor(self.vinculo)
        self.assertEqual(rev, self.revisor_b)

        # 3. Sem dono -> Recai no primeiro Gestor SecOps
        self.sis.dono = None
        self.sis.save()

        rev = determinar_revisor(self.vinculo)
        self.assertEqual(rev, self.user_gestor)

        # 4. Nenhum revisor elegível (alerta emitido no log)
        # Desativa temporariamente gestor secops
        self.user_gestor.is_active = False
        self.user_gestor.save()

        with self.assertLogs("gatekeeper.audit", level="WARNING") as cm:
            abrir_campanha(
                nome="Campanha Alerta",
                prazo=timezone.localdate() + timezone.timedelta(days=10),
                criada_por=self.revisor_a,
            )
            self.assertTrue(any("REVIEW_UNASSIGNED_ITEM" in msg for msg in cm.output))
        self.user_gestor.is_active = True
        self.user_gestor.save()

    def test_15_3_segregacao_ninguem_revisa_o_proprio_acesso(self):
        """15.8 (Segregação): Ninguém revisa o próprio acesso na abertura e na decisão."""
        # Colaborador é seu próprio gestor ou é o dono do sistema
        self.sis.dono = self.user_colab
        self.sis.save()

        # Na determinação de revisor, o dono do acesso é pulado
        rev = determinar_revisor(self.vinculo)
        self.assertNotEqual(rev, self.user_colab)

        # Se forçar o item a ter revisor = colaborador, registrar_decisao deve rejeitar com PermissionDenied
        item = ItemRevisao.objects.create(
            campanha=self.campanha,
            vinculo=self.vinculo,
            revisor=self.user_colab,
            decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
        )
        with self.assertRaises(PermissionDenied):
            registrar_decisao(
                item_id=item.pk,
                decisao=ItemRevisao.DecisaoRevisao.MANTER,
                justificativa="Auto-aprovação indevida",
                usuario=self.user_colab,
            )

    def test_15_4_autorizacao_por_objeto_idor_retorna_404(self):
        """15.8 (Objeto/IDOR): Revisor A recebe 404 estrito ao tentar decidir item do revisor B."""
        item_b = ItemRevisao.objects.create(
            campanha=self.campanha,
            vinculo=self.vinculo,
            revisor=self.revisor_b,
            decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
        )

        # Revisor A autentica e tenta submeter decisão no item de B
        self.client.force_login(self.revisor_a)
        url = reverse("decidir_revisao", kwargs={"item_id": item_b.pk})
        resp = self.client.post(
            url,
            {"decisao": "MANTER", "justificativa": "Tentativa de IDOR cruzada entre gestores"},
        )
        self.assertEqual(resp.status_code, 404)
        item_b.refresh_from_db()
        self.assertEqual(item_b.decisao, ItemRevisao.DecisaoRevisao.PENDENTE)

    def test_15_5_maquina_de_estados_campanha_encerrada_imutavel(self):
        """15.8 (Estado): Não decide em campanha ENCERRADA; ENCERRADA não reabre."""
        item = ItemRevisao.objects.create(
            campanha=self.campanha,
            vinculo=self.vinculo,
            revisor=self.revisor_a,
            decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
        )

        # Encerra campanha
        encerrar_campanha(self.campanha.pk, self.user_gestor, forcar=True)
        self.campanha.refresh_from_db()
        self.assertEqual(self.campanha.status, CampanhaRevisao.StatusCampanha.ENCERRADA)

        # Tentativa de registrar decisão em campanha encerrada
        with self.assertRaises(ValidationError) as ctx:
            registrar_decisao(
                item_id=item.pk,
                decisao=ItemRevisao.DecisaoRevisao.MANTER,
                justificativa="Tentativa em campanha fechada",
                usuario=self.revisor_a,
            )
        self.assertIn("já encerradas", str(ctx.exception))

        # Tentativa de re-encerrar
        with self.assertRaises(ValidationError) as ctx_reabrir:
            encerrar_campanha(self.campanha.pk, self.user_gestor, forcar=True)
        self.assertIn("não pode ser reaberta", str(ctx_reabrir.exception))

    def test_15_6_justificativa_obrigatoria_para_revogar_e_manter_critico(self):
        """15.8 (Justificativa): REVOGAR e MANTER em sistema CRÍTICO sem justificativa (mín 20) são recusados."""
        v_critico = VinculoAcesso.objects.create(
            colaborador=self.colab,
            sistema=self.sis_critico,
            identificador_conta="lucas.aws",
            status=VinculoAcesso.StatusAcesso.ATIVO,
        )
        item_critico = ItemRevisao.objects.create(
            campanha=self.campanha,
            vinculo=v_critico,
            revisor=self.revisor_a,
            decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
        )

        # 1. MANTER em crítico com justificativa curta (< 20 caracteres)
        with self.assertRaises(ValidationError) as ctx_critico:
            registrar_decisao(
                item_id=item_critico.pk,
                decisao=ItemRevisao.DecisaoRevisao.MANTER,
                justificativa="Necessário",
                usuario=self.revisor_a,
            )
        self.assertIn("mínimo de 20 caracteres", str(ctx_critico.exception))

        # 2. REVOGAR com justificativa curta
        v_medio = VinculoAcesso.objects.create(
            colaborador=self.colab,
            sistema=self.sis_medio,
            identificador_conta="lucas.jira2",
            status=VinculoAcesso.StatusAcesso.ATIVO,
        )
        item_medio = ItemRevisao.objects.create(
            campanha=self.campanha,
            vinculo=v_medio,
            revisor=self.revisor_a,
            decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
        )
        with self.assertRaises(ValidationError) as ctx_revogar:
            registrar_decisao(
                item_id=item_medio.pk,
                decisao=ItemRevisao.DecisaoRevisao.REVOGAR,
                justificativa="Não usa mais",
                usuario=self.revisor_a,
            )
        self.assertIn("mínimo de 20 caracteres", str(ctx_revogar.exception))

        # 3. REVOGAR com justificativa válida (>= 20 caracteres)
        item_sucesso = registrar_decisao(
            item_id=item_medio.pk,
            decisao=ItemRevisao.DecisaoRevisao.REVOGAR,
            justificativa="Colaborador transferido de setor; acesso não mais aplicável à função",
            usuario=self.revisor_a,
        )
        self.assertEqual(item_sucesso.decisao, ItemRevisao.DecisaoRevisao.REVOGAR)

    def test_15_7_decisao_em_lote_rejeita_alta_e_critica(self):
        """15.8 (Lote): Decisão em lote recusada se incluir itens de criticidade ALTA ou CRÍTICA."""
        v_alta = VinculoAcesso.objects.create(
            colaborador=self.colab,
            sistema=self.sis,  # GitLab = ALTA
            identificador_conta="lucas.git_lote",
            status=VinculoAcesso.StatusAcesso.ATIVO,
        )
        v_baixa = VinculoAcesso.objects.create(
            colaborador=self.colab,
            sistema=self.sis_baixo,
            identificador_conta="lucas.wiki_lote",
            status=VinculoAcesso.StatusAcesso.ATIVO,
        )

        item_alta = ItemRevisao.objects.create(campanha=self.campanha, vinculo=v_alta, revisor=self.revisor_a)
        item_baixa = ItemRevisao.objects.create(campanha=self.campanha, vinculo=v_baixa, revisor=self.revisor_a)

        # Tentativa de lote com item ALTA incluído
        with self.assertRaises(ValidationError) as ctx:
            registrar_decisao_lote(
                itens_ids=[item_alta.pk, item_baixa.pk],
                decisao=ItemRevisao.DecisaoRevisao.MANTER,
                justificativa="",
                usuario=self.revisor_a,
            )
        self.assertIn("criticidade ALTA ou CRÍTICA", str(ctx.exception))

        # Via View (HTTP 400 Bad Request)
        self.client.force_login(self.revisor_a)
        url_lote = reverse("decidir_revisao_lote")
        resp = self.client.post(
            url_lote,
            {
                "itens_ids": f"{item_alta.pk},{item_baixa.pk}",
                "decisao": "MANTER",
                "justificativa": "",
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_15_8_revogacao_decorrente_gera_tarefa_ti_e_exige_evidencia(self):
        """15.8 (Revogação): REVOGAR gera tarefa para a TI; vínculo só muda de status com evidência."""
        v = VinculoAcesso.objects.create(
            colaborador=self.colab,
            sistema=self.sis_medio,
            identificador_conta="lucas.rev_ti",
            status=VinculoAcesso.StatusAcesso.ATIVO,
        )
        item = ItemRevisao.objects.create(campanha=self.campanha, vinculo=v, revisor=self.revisor_a)

        # Gestor decide REVOGAR
        registrar_decisao(
            item_id=item.pk,
            decisao=ItemRevisao.DecisaoRevisao.REVOGAR,
            justificativa="Acesso revogado durante auditoria trimestral de acessos corporativos",
            usuario=self.revisor_a,
        )

        # O vínculo continua ATIVO até a execução da TI
        v.refresh_from_db()
        self.assertEqual(v.status, VinculoAcesso.StatusAcesso.ATIVO)
        self.assertFalse(item.tarefa_revogada)

        # TI tenta executar sem evidência
        with self.assertRaises(ValidationError):
            executar_revogacao_revisao(item_id=item.pk, evidencia="", usuario=self.user_analista)

        # TI executa com evidência formal
        executar_revogacao_revisao(
            item_id=item.pk,
            evidencia="Ticket ITSM #44901 - Acesso desabilitado no console de administração",
            usuario=self.user_analista,
        )

        item.refresh_from_db()
        v.refresh_from_db()
        self.assertTrue(item.tarefa_revogada)
        self.assertEqual(v.status, VinculoAcesso.StatusAcesso.REVOGADO)
        self.assertEqual(v.revogado_por, self.user_analista)

    def test_15_9_offboarding_desativa_usuario_vinculado(self):
        """15.8 (Desligamento): Início do offboarding desativa imediatamente o login (is_active=False)."""
        self.assertTrue(self.colab.usuario.is_active)

        iniciar_offboarding(
            colaborador_id=self.colab.pk,
            responsavel=self.user_analista,
            motivo="Desligamento Imediato",
        )

        self.user_colab.refresh_from_db()
        self.assertFalse(self.user_colab.is_active)

    def test_15_10_auditoria_emite_review_decision_estruturado(self):
        """15.8 (Auditoria): REVIEW_DECISION emitido com revisor, item e decisão."""
        item = ItemRevisao.objects.create(
            campanha=self.campanha,
            vinculo=self.vinculo,
            revisor=self.revisor_a,
            decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
        )

        with self.assertLogs("gatekeeper.audit", level="INFO") as cm:
            registrar_decisao(
                item_id=item.pk,
                decisao=ItemRevisao.DecisaoRevisao.MANTER,
                justificativa="Acesso necessário para homologação de código",
                usuario=self.revisor_a,
            )
            self.assertTrue(any("REVIEW_DECISION" in msg for msg in cm.output))
