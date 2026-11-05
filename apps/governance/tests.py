"""
Testes Unitários & de Segurança para o Módulo de Governança & IAM (GateKeeper-DBF).

Cobre:
- Fase 0 (Emergência): Login obrigatório em todas as rotas (Secure by Default)
- Segregação de Funções (RBAC): Auditor, Analista TI e Gestor SecOps
- Não-Repúdio: Atribuição estrita a request.user (sem fallbacks automáticos)
- Mitigação de Stored XSS com data-confirm desacoplado
- Integridade do fluxo de revogação e cálculo de progresso de offboarding
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
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


class GovernanceSecurityAndModelTests(TestCase):
    def setUp(self):
        self.client = Client()

        # Grupos RBAC criados pela migração 0003
        self.grupo_auditor = Group.objects.get(name='Auditor')
        self.grupo_analista = Group.objects.get(name='Analista TI')
        self.grupo_gestor = Group.objects.get(name='Gestor SecOps')

        # Usuários por Perfil
        self.user_auditor = User.objects.create_user(
            username='auditor.externo',
            email='auditor@empresa.com.br',
            password='ComplexPassword123!'
        )
        self.user_auditor.groups.add(self.grupo_auditor)

        self.user_analista = User.objects.create_user(
            username='analista.secops',
            email='secops@empresa.com.br',
            password='ComplexPassword123!'
        )
        self.user_analista.groups.add(self.grupo_analista)

        self.user_gestor = User.objects.create_user(
            username='gestor.ciso',
            email='ciso@empresa.com.br',
            password='ComplexPassword123!',
            is_staff=True
        )
        self.user_gestor.groups.add(self.grupo_gestor)

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

    def test_01_autenticacao_obrigatoria_redireciona_anonimos(self):
        """0.1: Garante que qualquer acesso anônimo é redirecionado para a tela de login (Secure by Default)."""
        rotas = [
            reverse('dashboard'),
            reverse('colaborador_list'),
            reverse('colaborador_detail', kwargs={'pk': self.colaborador.pk}),
            reverse('sistema_list'),
            reverse('matriz_acesso'),
            reverse('offboarding_list'),
        ]

        for rota in rotas:
            resp = self.client.get(rota)
            self.assertEqual(resp.status_code, 302, f"Rota {rota} permitiu acesso sem login!")
            self.assertIn(reverse('login'), resp.headers['Location'])

    def test_02_tela_de_login_disponivel_sem_autenticacao(self):
        """Garante que a tela de login está acessível publicamente com formulário CSRF e inputs."""
        resp = self.client.get(reverse('login'))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'name="username"')
        self.assertContains(resp, 'name="password"')
        self.assertContains(resp, 'csrfmiddlewaretoken')

    def test_03_segregacao_funcoes_auditor_apenas_leitura(self):
        """0.2: Usuário do grupo Auditor visualiza painéis, mas é impedido de executar offboarding (403 Forbidden)."""
        self.client.force_login(self.user_auditor)

        # Leitura permitida
        self.assertEqual(self.client.get(reverse('dashboard')).status_code, 200)
        self.assertEqual(self.client.get(reverse('colaborador_list')).status_code, 200)
        self.assertEqual(self.client.get(reverse('sistema_list')).status_code, 200)

        # Escrita/Ação bloqueada com 403 Forbidden
        resp_iniciar = self.client.post(
            reverse('iniciar_offboarding', kwargs={'pk': self.colaborador.pk}),
            {'motivo_desligamento': 'Auditor tentando desligar'}
        )
        self.assertEqual(resp_iniciar.status_code, 403)

    def test_04_analista_ti_executa_offboarding_com_nao_repudio_estrito(self):
        """0.2 e 0.3: Analista TI possui permissão para executar offboarding e seu login é gravado estritamente."""
        self.client.force_login(self.user_analista)

        # Concede acesso
        v = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.vpn,
            identificador_conta='carlos.vpn',
            concedido_por=self.user_gestor
        )

        # Inicia Offboarding
        resp_iniciar = self.client.post(
            reverse('iniciar_offboarding', kwargs={'pk': self.colaborador.pk}),
            {'motivo_desligamento': 'Desligamento formal test'}
        )
        self.assertEqual(resp_iniciar.status_code, 302)

        processo = ProcessoOffboarding.objects.get(colaborador=self.colaborador)
        # Não-repúdio: o responsável gravado DEVE ser estritamente self.user_analista
        self.assertEqual(processo.responsavel_ti, self.user_analista)

        # Revoga item
        item = processo.itens_checklist.first()
        resp_revogar = self.client.post(
            reverse('revogar_item_offboarding', kwargs={'pk': processo.pk, 'item_id': item.pk}),
            {'evidencia_revogacao': 'Ticket GLPI #5555'}
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
            data_admissao=timezone.now().date()
        )

        resp = self.client.get(reverse('colaborador_detail', kwargs={'pk': colab_xss.pk}))
        self.assertEqual(resp.status_code, 200)

        # Não deve haver onclick com código inline
        self.assertNotContains(resp, 'onclick="return confirm')
        # Deve utilizar o atributo desacoplado data-confirm
        self.assertContains(resp, 'data-confirm=')
