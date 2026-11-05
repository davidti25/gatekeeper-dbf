"""
Testes Unitários para o Módulo de Governança & IAM (GateKeeper-DBF).

Garante integridade nas regras de negócio de vinculação de acessos,
cálculo de progresso de offboarding e compliance de identidade.
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import (
    Localidade,
    Departamento,
    Cargo,
    Sistema,
    PerfilAcesso,
    Colaborador,
    VinculoAcesso,
    ProcessoOffboarding,
    ItemChecklistOffboarding,
)

User = get_user_model()


class GovernanceModelTests(TestCase):
    def setUp(self):
        self.client = Client()

        # Usuário analista de TI
        self.analista = User.objects.create_user(
            username='analista.secops',
            email='secops@empresa.com.br',
            password='ComplexPassword123!',
            is_staff=True
        )

        # Localidade & Setor
        self.matriz = Localidade.objects.create(
            nome='Sede São Paulo',
            codigo='SP-MATRIZ',
            cidade='São Paulo',
            estado='SP'
        )
        self.ti = Departamento.objects.create(
            nome='Tecnologia da Informação',
            sigla='TI',
            descricao='Setor de TI e Cibersegurança'
        )
        self.cargo = Cargo.objects.create(
            nome='Analista de SOC',
            departamento=self.ti
        )

        # Sistemas
        self.vpn = Sistema.objects.create(
            nome='VPN Corporativa WireGuard',
            tipo=Sistema.TipoSistema.VPN,
            criticidade=Sistema.Criticidade.ALTA,
            armazena_dados_lgpd=False,
            gestor_responsavel='Equipe de SecOps',
            instrucoes_revogacao='Remover chave pública do servidor WireGuard.'
        )
        self.perfil_vpn = PerfilAcesso.objects.create(
            sistema=self.vpn,
            nome='Acesso Full SOC',
            nivel_privilegio=PerfilAcesso.NivelPrivilegio.ADMIN
        )

        self.erp = Sistema.objects.create(
            nome='ERP Corporativo',
            tipo=Sistema.TipoSistema.SAAS,
            criticidade=Sistema.Criticidade.CRITICA,
            armazena_dados_lgpd=True,
            gestor_responsavel='TI Interna',
            instrucoes_revogacao='Inativar cadastro do usuário no painel master.'
        )

        # Colaborador
        self.colaborador = Colaborador.objects.create(
            nome_completo='Carlos Santos',
            matricula='TI-0042',
            email_corporativo='carlos.santos@empresa.com.br',
            localidade=self.matriz,
            departamento=self.ti,
            cargo=self.cargo,
            status=Colaborador.StatusColaborador.ATIVO,
            data_admissao=timezone.now().date()
        )

    def test_criacao_modelos_basicos(self):
        """Valida que as representações em string e relacionamentos funcionam como esperado."""
        self.assertEqual(str(self.matriz), "Sede São Paulo (SP-MATRIZ)")
        self.assertEqual(str(self.ti), "Tecnologia da Informação (TI)")
        self.assertEqual(str(self.cargo), "Analista de SOC - TI")
        self.assertIn("Carlos Santos", str(self.colaborador))

    def test_vinculo_acesso_e_contagem(self):
        """Testa concessão de acessos e cálculo dinâmico de acessos ativos do colaborador."""
        self.assertEqual(self.colaborador.total_acessos_ativos, 0)

        # Concede acesso VPN
        vinculo1 = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.vpn,
            perfil_acesso=self.perfil_vpn,
            identificador_conta='carlos.santos',
            concedido_por=self.analista
        )
        self.assertEqual(self.colaborador.total_acessos_ativos, 1)

        # Concede acesso ERP
        vinculo2 = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.erp,
            identificador_conta='carlos.santos@empresa.com.br',
            concedido_por=self.analista
        )
        self.assertEqual(self.colaborador.total_acessos_ativos, 2)

        # Revoga um dos acessos
        vinculo1.status = VinculoAcesso.StatusAcesso.REVOGADO
        vinculo1.data_revogacao = timezone.now()
        vinculo1.revogado_por = self.analista
        vinculo1.save()

        self.assertEqual(self.colaborador.total_acessos_ativos, 1)

    def test_processo_offboarding_progresso(self):
        """Testa o cálculo de progresso percentual e status de encerramento do offboarding."""
        v1 = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.vpn,
            identificador_conta='carlos.santos',
            concedido_por=self.analista
        )
        v2 = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.erp,
            identificador_conta='carlos.santos@empresa.com.br',
            concedido_por=self.analista
        )

        offboarding = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO
        )

        item1 = ItemChecklistOffboarding.objects.create(
            processo=offboarding,
            vinculo_acesso=v1
        )
        item2 = ItemChecklistOffboarding.objects.create(
            processo=offboarding,
            vinculo_acesso=v2
        )

        self.assertEqual(offboarding.total_itens, 2)
        self.assertEqual(offboarding.total_revogados, 0)
        self.assertEqual(offboarding.percentual_concluido, 0)

        # Revoga primeiro item
        item1.revogado = True
        item1.data_revogacao = timezone.now()
        item1.responsavel_revogacao = self.analista
        item1.evidencia_revogacao = 'Conta VPN removida. Chamado #1234'
        item1.save()

        self.assertEqual(offboarding.total_revogados, 1)
        self.assertEqual(offboarding.percentual_concluido, 50)

        # Revoga segundo item
        item2.revogado = True
        item2.data_revogacao = timezone.now()
        item2.responsavel_revogacao = self.analista
        item2.evidencia_revogacao = 'Usuário inativado no ERP. Chamado #1235'
        item2.save()

        self.assertEqual(offboarding.total_revogados, 2)
        self.assertEqual(offboarding.percentual_concluido, 100)

    def test_views_dashboard_e_listagens(self):
        """Garante que as principais views respondem com HTTP 200 e contexto adequado."""
        # Dashboard
        resp_dash = self.client.get(reverse('dashboard'))
        self.assertEqual(resp_dash.status_code, 200)
        self.assertIn('colaboradores_ativos', resp_dash.context)

        # Lista de Colaboradores
        resp_colab = self.client.get(reverse('colaborador_list'))
        self.assertEqual(resp_colab.status_code, 200)

        # Detalhe do Colaborador
        resp_detail = self.client.get(reverse('colaborador_detail', kwargs={'pk': self.colaborador.pk}))
        self.assertEqual(resp_detail.status_code, 200)

        # Inventário de Sistemas
        resp_sistemas = self.client.get(reverse('sistema_list'))
        self.assertEqual(resp_sistemas.status_code, 200)

        # Matriz RBAC
        resp_matriz = self.client.get(reverse('matriz_acesso'))
        self.assertEqual(resp_matriz.status_code, 200)

    def test_fluxo_completo_offboarding_web(self):
        """Testa o fluxo guiado de offboarding pela interface web: iniciar, revogar item e emitir relatório."""
        self.client.force_login(self.analista)

        # Concede um acesso para o colaborador
        vinculo = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.vpn,
            identificador_conta='carlos.vpn',
            concedido_por=self.analista
        )

        # 1. Iniciar Offboarding via POST
        resp_iniciar = self.client.post(
            reverse('iniciar_offboarding', kwargs={'pk': self.colaborador.pk}),
            {'motivo_desligamento': 'Desligamento Teste'}
        )
        self.assertEqual(resp_iniciar.status_code, 302)

        processo = ProcessoOffboarding.objects.get(colaborador=self.colaborador)
        self.assertEqual(processo.total_itens, 1)
        self.assertEqual(processo.total_revogados, 0)
        self.assertEqual(processo.status, ProcessoOffboarding.StatusOffboarding.INICIADO)

        # 2. Revogar Item do Checklist via POST
        item = processo.itens_checklist.first()
        resp_revogar = self.client.post(
            reverse('revogar_item_offboarding', kwargs={'pk': processo.pk, 'item_id': item.pk}),
            {
                'evidencia_revogacao': 'Ticket GLPI #9999 - Chave revogada',
                'observacao': 'Tudo ok'
            }
        )
        self.assertEqual(resp_revogar.status_code, 302)

        # Recarrega processo e colaborador
        processo.refresh_from_db()
        self.colaborador.refresh_from_db()

        self.assertEqual(processo.total_revogados, 1)
        self.assertEqual(processo.percentual_concluido, 100)
        self.assertEqual(processo.status, ProcessoOffboarding.StatusOffboarding.CONCLUIDO)
        self.assertEqual(self.colaborador.status, Colaborador.StatusColaborador.DESLIGADO)

        # 3. Emissão de Relatório Formal
        resp_relatorio = self.client.get(reverse('offboarding_relatorio', kwargs={'pk': processo.pk}))
        self.assertEqual(resp_relatorio.status_code, 200)
        self.assertContains(resp_relatorio, "CIS Controls v8")
        self.assertContains(resp_relatorio, "Carlos Santos")
