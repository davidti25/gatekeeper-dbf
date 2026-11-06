"""
Testes de Regressão das Fases 16 e 17: Operação, SLAs, Notificações e Ciclo de Vida Completo.

Contempla:
- 16.1: Tempo até a revogação (indicador de auditoria, SLA de 24h, mediana e pior caso).
- 16.2: Comando 'enviar_lembretes' (e-mail sem dados confidenciais, apenas link, MFA obrigatório).
- 16.3: Comando 'importar_colaboradores' (neutralização de CSV formula injection, --simular/--aplicar, não-desligamento).
- 17.1: Fluxo de concessão: Solicitar -> Aprovar -> Conceder (segregação e evidência).
- 17.2: Pacotes de acesso por cargo (perfis padrão).
- 17.3: Mudança de cargo abre mini-revisão automática com novo gestor.
"""

import tempfile
from datetime import date
from io import StringIO

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core import mail
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.governance.models import (
    Cargo,
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    PerfilAcesso,
    ProcessoOffboarding,
    Sistema,
    SolicitacaoAcesso,
    VinculoAcesso,
)
from apps.governance.services import (
    alterar_cargo_colaborador,
    aprovar_solicitacao,
    conceder_acesso,
    solicitar_acesso,
)
from apps.governance.tests.base import (
    setup_fase10_fixtures,
)

User = get_user_model()


class OperacaoECicloVidaTests(TestCase):
    def setUp(self):
        setup_fase10_fixtures(self)

        self.grupo_revisor, _ = Group.objects.get_or_create(name="Revisor")

        self.colab_op = Colaborador.objects.create(
            nome_completo="Carlos Operacional",
            matricula="SEC-0088",
            email_corporativo="carlos.op@empresa.com.br",
            departamento=self.dept,
            cargo=self.cargo,
            localidade=self.loc,
            data_admissao=date(2025, 1, 10),
            status=Colaborador.StatusColaborador.ATIVO,
        )

        self.sis_critico = Sistema.objects.create(
            nome="AWS Cloud Production Core",
            tipo=Sistema.TipoSistema.SAAS,
            criticidade=Sistema.Criticidade.CRITICA,
            gestor_responsavel="SecOps Cloud",
            dono=self.user_gestor,
        )

        self.perfil_admin = PerfilAcesso.objects.create(
            sistema=self.sis_critico,
            nome="Cloud Administrator",
            nivel_privilegio=PerfilAcesso.NivelPrivilegio.ADMIN,
        )

    # ==========================================================================
    # Fase 16.1: Tempo até a revogação (indicador de auditoria)
    # ==========================================================================
    def test_16_1_tempo_ate_revogacao_calcula_sla_corretamente(self):
        """16.1: Tempo até revogação calcula intervalo entre data_desligamento e conclusão; destaca SLA > 24h."""
        hoje = timezone.localdate()
        colab = Colaborador.objects.create(
            nome_completo="Marcos Ex-Colaborador",
            matricula="FIN-0010",
            email_corporativo="marcos@empresa.com.br",
            departamento=self.dept,
            cargo=self.cargo,
            localidade=self.loc,
            data_admissao=date(2024, 1, 1),
            data_desligamento=hoje,
            status=Colaborador.StatusColaborador.DESLIGADO,
        )
        proc = ProcessoOffboarding.objects.create(
            colaborador=colab,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.CONCLUIDO,
            concluido_em=timezone.now(),
        )
        v = VinculoAcesso.objects.create(
            colaborador=colab,
            sistema=self.sis,
            identificador_conta="marcos.git",
            status=VinculoAcesso.StatusAcesso.REVOGADO,
            data_revogacao=timezone.now(),
        )
        ItemChecklistOffboarding.objects.create(
            processo=proc,
            vinculo_acesso=v,
            status=ItemChecklistOffboarding.StatusItem.REVOGADO,
            revogado=True,
            data_revogacao=timezone.now(),
            evidencia_revogacao="Chamado #9090",
        )

        horas = proc.tempo_ate_revogacao_horas
        self.assertIsNotNone(horas)
        self.assertGreaterEqual(horas, 0.0)
        self.assertFalse(proc.acima_do_sla)  # Concluído no mesmo dia <= 24h

        # Processo antigo excedendo SLA
        colab_atrasado = Colaborador.objects.create(
            nome_completo="Aline Ex-Colaboradora",
            matricula="FIN-0011",
            email_corporativo="aline@empresa.com.br",
            departamento=self.dept,
            cargo=self.cargo,
            localidade=self.loc,
            data_admissao=date(2024, 1, 1),
            data_desligamento=hoje - timezone.timedelta(days=3),  # 72 horas atrás
            status=Colaborador.StatusColaborador.DESLIGADO,
        )
        proc_atrasado = ProcessoOffboarding.objects.create(
            colaborador=colab_atrasado,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.CONCLUIDO,
            concluido_em=timezone.now(),
        )
        self.assertTrue(proc_atrasado.acima_do_sla)
        self.assertGreater(proc_atrasado.tempo_ate_revogacao_horas, 24.0)

    # ==========================================================================
    # Fase 16.2: Avisos por E-mail (Segurança & Link Seguro)
    # ==========================================================================
    @override_settings(
        EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
        GATEKEEPER_BASE_URL="https://gatekeeper.empresa.com.br",
    )
    def test_16_2_comando_enviar_lembretes_sem_dados_confidenciais(self):
        """16.2: enviar_lembretes notifica sem trafegar nomes de sistemas, contas ou dados de acesso no e-mail."""
        mail.outbox.clear()
        out = StringIO()

        with self.assertLogs("gatekeeper.audit", level="INFO") as cm:
            call_command("enviar_lembretes", stdout=out)
            self.assertTrue(any("ALERT_REMINDERS_SENT" in msg for msg in cm.output))

        # Pelo menos um e-mail disparado para o responsável de TI com processo aberto
        self.assertGreater(len(mail.outbox), 0)
        msg = mail.outbox[0]

        # Garantias de segurança (16.2)
        self.assertIn("https://gatekeeper.empresa.com.br", msg.body)
        self.assertIn("MFA", msg.body)
        # NUNCA expor detalhes confidenciais de credenciais ou contas
        self.assertNotIn("AWS Cloud", msg.body)
        self.assertNotIn("senha", msg.body.lower())
        self.assertNotIn("lucas.git", msg.body)

    # ==========================================================================
    # Fase 16.3: Importação de Colaboradores via CSV
    # ==========================================================================
    def test_16_3_importacao_csv_simular_e_aplicar_e_sanitizacao_formula(self):
        """16.3: Importação com sanitização de fórmula, --simular não grava, ausentes viram 'a verificar'."""
        conteudo_csv = (
            "matricula;nome_completo;email_corporativo;departamento;cargo;localidade;data_admissao\n"
            "RH-9901;Beatriz Nova;beatriz.nova@empresa.com.br;RH;Analista RH;SP-MATRIZ;2026-02-01\n"
            "=cmd|' /C calc'!A0;Injecao Formula;injecao@empresa.com.br;TI;Dev;SP-MATRIZ;2026-02-01\n"
        )

        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write(conteudo_csv)
            f_path = f.name

        out = StringIO()

        # 1. Modo Simulação: não grava no banco
        call_command("importar_colaboradores", f_path, "--simular", stdout=out)
        self.assertFalse(Colaborador.objects.filter(matricula="RH-9901").exists())

        # 2. Modo Aplicar: grava e sanitiza injeção de fórmula
        with self.assertLogs("gatekeeper.audit", level="INFO") as cm:
            call_command("importar_colaboradores", f_path, "--aplicar", stdout=out)
            self.assertTrue(any("HR_IMPORT" in msg for msg in cm.output))

        self.assertTrue(Colaborador.objects.filter(matricula="RH-9901").exists())

        # Sanitização da injeção de fórmula
        colab_inj = Colaborador.objects.get(email_corporativo="injecao@empresa.com.br")
        self.assertTrue(colab_inj.matricula.startswith("'="))

        # Colaborador pré-existente (Carlos Operacional) não estava no CSV e NÃO foi desligado
        self.colab_op.refresh_from_db()
        self.assertEqual(self.colab_op.status, Colaborador.StatusColaborador.ATIVO)

    # ==========================================================================
    # Fase 17.1: Ciclo de Vida: Solicitação -> Aprovação -> Concessão
    # ==========================================================================
    def test_17_1_fluxo_concessao_solicitar_aprovar_conceder(self):
        """17.1: Solicitar (justificativa 20 carac.) -> Aprovar (segregação / dono) -> Conceder (TI com evidência)."""
        # 1. Solicitação sem justificativa mínima
        with self.assertRaises(ValidationError) as ctx:
            solicitar_acesso(
                colaborador_id=self.colab_op.pk,
                sistema_id=self.sis_critico.pk,
                identificador_conta="carlos.aws",
                justificativa="Preciso de acesso",
                chamado="INC-9912",
                usuario=self.user_analista,
                perfil_id=self.perfil_admin.pk,
            )
        self.assertIn("mínimo de 20 caracteres", str(ctx.exception))

        # Solicitação válida
        solic = solicitar_acesso(
            colaborador_id=self.colab_op.pk,
            sistema_id=self.sis_critico.pk,
            identificador_conta="carlos.aws",
            justificativa="Acesso administrativo para sustentar o cluster Kubernetes de produção",
            chamado="INC-9912",
            usuario=self.user_analista,
            perfil_id=self.perfil_admin.pk,
        )
        self.assertEqual(solic.status, SolicitacaoAcesso.StatusSolicitacao.PENDENTE_APROVACAO)

        # 2. Segregação: quem solicita não pode aprovar
        with self.assertRaises(PermissionDenied):
            aprovar_solicitacao(solic.pk, usuario=self.user_analista, aprovado=True)

        # Sistema crítico exige dono (user_gestor)
        outro_user = User.objects.create_user(
            username="outro.gestor", email="outro@empresa.com.br", password="ComplexPassword123!"
        )
        with self.assertRaises(PermissionDenied):
            aprovar_solicitacao(solic.pk, usuario=outro_user, aprovado=True)

        # Dono do sistema aprova
        aprovar_solicitacao(solic.pk, usuario=self.user_gestor, aprovado=True)
        solic.refresh_from_db()
        self.assertEqual(solic.status, SolicitacaoAcesso.StatusSolicitacao.APROVADO)
        self.assertEqual(solic.aprovado_por, self.user_gestor)

        # 3. Concessão técnica pela TI exige evidência
        with self.assertRaises(ValidationError):
            conceder_acesso(solic.pk, evidencia="", usuario=self.user_analista)

        # Concessão válida
        vinculo = conceder_acesso(
            solic.pk,
            evidencia="Ticket AWS IAM #8892 - Usuário provisionado no grupo SecOps-Prod",
            usuario=self.user_analista,
        )
        solic.refresh_from_db()
        self.assertEqual(solic.status, SolicitacaoAcesso.StatusSolicitacao.CONCEDIDO)
        self.assertEqual(vinculo.status, VinculoAcesso.StatusAcesso.ATIVO)
        self.assertEqual(vinculo.concedido_por, self.user_analista)

    # ==========================================================================
    # Fase 17.2: Pacotes de Acesso por Cargo
    # ==========================================================================
    def test_17_2_pacotes_de_acesso_por_cargo(self):
        """17.2: Cargo possui conjunto de perfis padrão (pacote por cargo) para reduzir privilege creep."""
        self.cargo.perfis_padrao.add(self.perfil_admin)
        self.assertIn(self.perfil_admin, self.cargo.perfis_padrao.all())

    # ==========================================================================
    # Fase 17.3: Mudança de Cargo abre Mini-Revisão Automática
    # ==========================================================================
    def test_17_3_mudanca_de_cargo_dispara_mini_revisao(self):
        """17.3: Alteração de cargo/setor com vínculos ativos dispara mini-revisão automática com novo gestor."""
        # Cria vínculo ativo para Carlos
        VinculoAcesso.objects.create(
            colaborador=self.colab_op,
            sistema=self.sis,
            identificador_conta="carlos.git",
            status=VinculoAcesso.StatusAcesso.ATIVO,
            concedido_por=self.user_analista,
        )

        novo_depto = Departamento.objects.create(nome="Controladoria", sigla="CTRL")
        novo_cargo = Cargo.objects.create(nome="Auditor Pleno", departamento=novo_depto)

        colab_atualizado, mini_campanha = alterar_cargo_colaborador(
            colaborador_id=self.colab_op.pk,
            novo_cargo_id=novo_cargo.pk,
            novo_departamento_id=novo_depto.pk,
            usuario=self.user_gestor,
        )

        self.assertEqual(colab_atualizado.cargo, novo_cargo)
        self.assertEqual(colab_atualizado.departamento, novo_depto)
        self.assertIsNotNone(mini_campanha)
        self.assertIn("Mini-Revisão", mini_campanha.nome)
        self.assertEqual(mini_campanha.itens.count(), 1)
