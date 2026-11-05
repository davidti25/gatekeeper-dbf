"""
Testes Unitários para o Módulo de Governança & IAM (GateKeeper-DBF).

Garante integridade nas regras de negócio de vinculação de acessos,
cálculo de progresso de offboarding e compliance de identidade.
"""

from django.test import TestCase
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
        # Usuário analista de TI
        self.analista = User.objects.create_user(
            username='analista.secops',
            email='secops@empresa.com.br',
            password='ComplexPassword123!'
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
            gestor_responsavel='Equipe de SecOps'
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
            gestor_responsavel='TI Interna'
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
        # Cria vínculos
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

        # Inicia processo de offboarding
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
        item1.evidencia_revogacao = 'Conta VPN removida no painel WireGuard. Ticket #1234'
        item1.save()

        self.assertEqual(offboarding.total_revogados, 1)
        self.assertEqual(offboarding.percentual_concluido, 50)

        # Revoga segundo item
        item2.revogado = True
        item2.data_revogacao = timezone.now()
        item2.responsavel_revogacao = self.analista
        item2.evidencia_revogacao = 'Usuário desativado no ERP. Ticket #1235'
        item2.save()

        self.assertEqual(offboarding.total_revogados, 2)
        self.assertEqual(offboarding.percentual_concluido, 100)
