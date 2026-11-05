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
from django.db.models import ProtectedError
from django.core.exceptions import ValidationError
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
from .forms import RevogacaoItemForm
from .services import revogar_item_checklist

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

    def test_06_master_root_acesso_total(self):
        """Valida que o usuário master root (superuser) possui acesso e execução irrestrita em todos os módulos."""
        root_user = User.objects.create_superuser(
            username='root.test',
            email='root.test@gatekeeper.local',
            password='RootDev2026!'
        )
        self.client.force_login(root_user)

        # Acesso às telas principais
        self.assertEqual(self.client.get(reverse('dashboard')).status_code, 200)
        self.assertEqual(self.client.get(reverse('colaborador_list')).status_code, 200)
        self.assertEqual(self.client.get(reverse('sistema_list')).status_code, 200)
        self.assertEqual(self.client.get(reverse('matriz_acesso')).status_code, 200)

        # Execução de ação privilegiada
        resp = self.client.post(
            reverse('iniciar_offboarding', kwargs={'pk': self.colaborador.pk}),
            {'motivo_desligamento': 'Root override test'}
        )
        self.assertEqual(resp.status_code, 302)
        processo = ProcessoOffboarding.objects.get(colaborador=self.colaborador)
        self.assertEqual(processo.responsavel_ti, root_user)


class Phase1AuditAndIntegrityTests(TestCase):
    """
    Testes de Integridade da Auditoria & Regras de Negócio (Fase 1).
    Valida:
    - 1.1: on_delete=models.PROTECT contra expurgo acidental de dados
    - 1.2: Rastreabilidade temporal com django-simple-history
    - 1.3: Transações atômicas, idempotência e bloqueio de concorrência
    - 1.4: Validação estrita de evidências em sistemas críticos e escopo LGPD
    - 1.5: Suporte a recontratação (UniqueConstraint condicional)
    """
    def setUp(self):
        self.client = Client()

        self.grupo_analista = Group.objects.get(name='Analista TI')
        self.user_analista = User.objects.create_user(
            username='secops.analyst',
            email='analyst@empresa.com.br',
            password='ComplexPassword123!'
        )
        self.user_analista.groups.add(self.grupo_analista)

        self.matriz = Localidade.objects.create(
            nome='Filial Salvador',
            codigo='SSA-01',
            cidade='Salvador',
            estado='BA'
        )
        self.depto = Departamento.objects.create(
            nome='Operações Financeiras',
            sigla='FIN',
            descricao='Controladoria e Financeiro'
        )
        self.cargo = Cargo.objects.create(
            nome='Analista Financeiro Pleno',
            departamento=self.depto
        )

        self.sistema_critico = Sistema.objects.create(
            nome='Internet Banking PJ',
            tipo=Sistema.TipoSistema.SAAS,
            criticidade=Sistema.Criticidade.CRITICA,
            armazena_dados_lgpd=True,
            gestor_responsavel='Segurança da Informação'
        )

        self.sistema_interno = Sistema.objects.create(
            nome='Wiki Interna Redmine',
            tipo=Sistema.TipoSistema.ONPREM,
            criticidade=Sistema.Criticidade.BAIXA,
            armazena_dados_lgpd=False,
            gestor_responsavel='TI Suporte'
        )

        self.colaborador = Colaborador.objects.create(
            nome_completo='Mariana Oliveira',
            matricula='FIN-8812',
            email_corporativo='mariana.oliveira@empresa.com.br',
            localidade=self.matriz,
            departamento=self.depto,
            cargo=self.cargo,
            status=Colaborador.StatusColaborador.ATIVO,
            data_admissao=timezone.now().date()
        )

    def test_10_protecao_exclusao_acidental_on_delete_protect(self):
        """1.1: Colaboradores com vínculos de acesso ou processos de offboarding não podem ser deletados (PROTECT)."""
        vinculo = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema_interno,
            identificador_conta='mariana.wiki',
            concedido_por=self.user_analista
        )

        # Tentativa de exclusão do colaborador com vínculo deve falhar
        with self.assertRaises(ProtectedError):
            self.colaborador.delete()

        # Cria processo e item de checklist
        processo = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO
        )
        item = ItemChecklistOffboarding.objects.create(
            processo=processo,
            vinculo_acesso=vinculo
        )

        # Tentativa de exclusão do vínculo com item no checklist deve falhar
        with self.assertRaises(ProtectedError):
            vinculo.delete()

    def test_11_bloqueio_concessao_acesso_colaborador_desligado_ou_em_offboarding(self):
        """1.1: Regra de negócio impede conceder novos acessos a colaboradores desligados ou em offboarding."""
        # 1. Colaborador em processo de offboarding ativo
        ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO
        )

        novo_vinculo = VinculoAcesso(
            colaborador=self.colaborador,
            sistema=self.sistema_critico,
            identificador_conta='mariana.banking',
            concedido_por=self.user_analista
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
            identificador_conta='mariana.wiki2',
            concedido_por=self.user_analista
        )
        with self.assertRaises(ValidationError) as ctx:
            novo_vinculo_desligado.clean()
        self.assertIn("colaborador já desligado", str(ctx.exception))

    def test_12_servico_revogacao_atomica_e_idempotencia(self):
        """1.3: Serviço revogar_item_checklist executa atomicamente e rejeita sobrescrita de itens já resolvidos."""
        vinculo = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema_interno,
            identificador_conta='mariana.wiki',
            concedido_por=self.user_analista
        )
        processo = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO
        )
        item = ItemChecklistOffboarding.objects.create(
            processo=processo,
            vinculo_acesso=vinculo
        )

        # 1. Primeira execução: Sucesso
        item_revogado, proc_atualizado = revogar_item_checklist(
            item_id=item.pk,
            responsavel=self.user_analista,
            evidencia="Ticket ITSM #10293",
            observacao="Conta desativada",
            status=ItemChecklistOffboarding.StatusItem.REVOGADO
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
                status=ItemChecklistOffboarding.StatusItem.REVOGADO
            )
        self.assertIn("já foi finalizado anteriormente", str(ctx.exception))

    def test_13_validacao_formulario_evidencia_obrigatoria_sistemas_criticos_e_lgpd(self):
        """1.4: RevogacaoItemForm exige evidência em sistemas críticos/LGPD e rejeita descrições genéricas."""
        vinculo_critico = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema_critico,
            identificador_conta='mariana.ib',
            concedido_por=self.user_analista
        )
        processo = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista
        )
        item_critico = ItemChecklistOffboarding.objects.create(
            processo=processo,
            vinculo_acesso=vinculo_critico
        )

        # 1. Sem evidência em sistema crítico/LGPD: Inválido
        form_vazio = RevogacaoItemForm(
            data={'status': 'REVOGADO', 'evidencia_revogacao': ''},
            item=item_critico
        )
        self.assertFalse(form_vazio.is_valid())
        self.assertIn('evidencia_revogacao', form_vazio.errors)

        # 2. Com evidência genérica ("revogado manualmente"): Inválido
        form_generico = RevogacaoItemForm(
            data={'status': 'REVOGADO', 'evidencia_revogacao': 'Revogado manualmente'},
            item=item_critico
        )
        self.assertFalse(form_generico.is_valid())
        self.assertIn('evidencia_revogacao', form_generico.errors)

        # 3. Com evidência auditável (Ticket #...): Válido
        form_valido = RevogacaoItemForm(
            data={'status': 'REVOGADO', 'evidencia_revogacao': 'Ticket GLPI #8841 - Chave revogada'},
            item=item_critico
        )
        self.assertTrue(form_valido.is_valid())

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

    def test_15_suporte_recontratacao_colaborador(self):
        """1.5: Suporte a recontratação com histórico preservado e sem colisão de UniqueConstraint."""
        # Primeiro ciclo: offboarding concluído
        processo_1 = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.CONCLUIDO,
            concluido_em=timezone.now()
        )

        # Recontratação: Colaborador reativado
        self.colaborador.status = Colaborador.StatusColaborador.ATIVO
        self.colaborador.save()

        # Segundo ciclo de offboarding futuro: Deve ser permitido criar novo processo ativo
        processo_2 = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=self.user_analista,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO
        )
        self.assertIsNotNone(processo_2.pk)
        self.assertNotEqual(processo_1.pk, processo_2.pk)
        self.assertEqual(self.colaborador.processos_offboarding.count(), 2)


class Phase2PlatformAndHardeningTests(TestCase):
    """
    Testes de Plataforma & Hardening de Configuração (Fase 2).
    Valida:
    - 2.3: Content Security Policy (CSP) sem 'unsafe-inline'
    - 2.3: Front-end local desvinculado de CDNs externas (LGPD / Supply Chain)
    - 2.4: Hardening de sessão, cookies e configurações de deploy
    - 2.4: Trilha de auditoria SOC em sinais de autenticação
    """
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='soc.auditor',
            email='soc@empresa.com.br',
            password='ComplexPassword123!'
        )
        grupo_auditor = Group.objects.get(name='Auditor')
        self.user.groups.add(grupo_auditor)

    def test_20_csp_headers_sem_unsafe_inline(self):
        """2.3: Cabeçalho Content-Security-Policy presente e bloqueando inline scripts externos."""
        resp = self.client.get(reverse('login'))
        self.assertEqual(resp.status_code, 200)

        self.assertIn('Content-Security-Policy', resp.headers)
        csp = resp.headers['Content-Security-Policy']

        # default-src 'self'
        self.assertIn("default-src 'self'", csp)
        # script-src 'self' sem 'unsafe-inline'
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("'unsafe-inline'", csp)
        # frame-ancestors 'none' (anti-clickjacking)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_21_recursos_estaticos_locais_sem_cdns_externos(self):
        """2.3: Front-end servido 100% de static/ sem dependência de CDNs ou envio de dados/IP para terceiros (LGPD)."""
        self.client.force_login(self.user)
        resp = self.client.get(reverse('dashboard'))
        self.assertEqual(resp.status_code, 200)

        # Não deve haver conexões externas para Google Fonts, CDN Tailwind ou Unpkg
        self.assertNotContains(resp, 'cdn.tailwindcss.com')
        self.assertNotContains(resp, 'unpkg.com')
        self.assertNotContains(resp, 'fonts.googleapis.com')
        self.assertNotContains(resp, 'fonts.gstatic.com')

        # Deve conter as rotas locais compiladas e servidas pelo WhiteNoise (com ou sem hash)
        content = resp.content.decode()
        self.assertIn('/static/fonts/fonts.', content)
        self.assertIn('/static/css/tailwind.min.', content)
        self.assertIn('/static/vendor/lucide.min.', content)
        self.assertIn('/static/js/app.', content)

    def test_22_sessao_e_hardening_cookies(self):
        """2.4: Validação de cookies de sessão de 8 horas e isolamento HttpOnly."""
        from django.conf import settings
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)
        self.assertEqual(settings.SESSION_COOKIE_AGE, 28800)
        self.assertTrue(settings.SESSION_EXPIRE_AT_BROWSER_CLOSE)
        self.assertEqual(settings.X_FRAME_OPTIONS, 'DENY')
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)

    def test_23_trilha_auditoria_soc_sinais(self):
        """2.4: Eventos de autenticação disparam logs estruturados para ingestão em SIEM."""
        import logging
        with self.assertLogs('gatekeeper.audit', level='INFO') as cm:
            # Login com sucesso
            self.client.login(username='soc.auditor', password='ComplexPassword123!')
            # Logout
            self.client.logout()

        logs_texto = "\n".join(cm.output)
        self.assertIn("AUTH_LOGIN_SUCCESS", logs_texto)
        self.assertIn("soc.auditor", logs_texto)
        self.assertIn("AUTH_LOGOUT", logs_texto)


