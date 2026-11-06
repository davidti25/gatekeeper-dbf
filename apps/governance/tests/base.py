"""
Fábricas de dados e utilitários compartilhados para a suíte de testes de Governança & IAM.
"""

from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils import timezone

from apps.governance.models import (
    CampanhaRevisao,
    Cargo,
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    ItemRevisao,
    Localidade,
    ProcessoOffboarding,
    Sistema,
    SolicitacaoAcesso,
    VinculoAcesso,
)

User = get_user_model()


def criar_usuario_com_totp(
    username, email, password="ComplexPassword123!", grupo_nome=None, is_staff=False, is_superuser=False
):
    """Cria um usuário com autenticador TOTP ativo no allauth."""
    if is_superuser:
        user = User.objects.create_superuser(username=username, email=email, password=password)
    else:
        user = User.objects.create_user(username=username, email=email, password=password, is_staff=is_staff)

    if grupo_nome:
        grupo, _ = Group.objects.get_or_create(name=grupo_nome)
        user.groups.add(grupo)

    Authenticator.objects.create(user=user, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"})
    return user


def criar_estrutura_organizacional():
    """Garante existência de Localidade, Departamento e Cargo padrão para testes."""
    loc, _ = Localidade.objects.get_or_create(
        codigo="SP-MATRIZ", defaults={"nome": "Sede São Paulo", "cidade": "São Paulo", "estado": "SP"}
    )
    dept, _ = Departamento.objects.get_or_create(
        sigla="TI", defaults={"nome": "Tecnologia da Informação", "descricao": "Setor de TI e Cibersegurança"}
    )
    cargo, _ = Cargo.objects.get_or_create(nome="Analista de SOC", defaults={"departamento": dept})
    return loc, dept, cargo


def criar_colaborador(
    nome="Carlos Santos",
    email="carlos@empresa.com.br",
    matricula="EMP-001",
    departamento=None,
    cargo=None,
    localidade=None,
    data_admissao="2026-01-01",
    status=Colaborador.StatusColaborador.ATIVO,
):
    """Cria colaborador com estrutura organizacional válida."""
    if not localidade or not departamento or not cargo:
        loc, dept, carg = criar_estrutura_organizacional()
        localidade = localidade or loc
        departamento = departamento or dept
        cargo = cargo or carg

    return Colaborador.objects.create(
        nome_completo=nome,
        matricula=matricula,
        email_corporativo=email,
        departamento=departamento,
        cargo=cargo,
        localidade=localidade,
        data_admissao=data_admissao,
        status=status,
    )


def criar_sistema(
    nome="VPN Corporativa WireGuard",
    tipo=Sistema.TipoSistema.VPN,
    criticidade=Sistema.Criticidade.ALTA,
    armazena_lgpd=False,
):
    """Cria um sistema cadastrado."""
    return Sistema.objects.create(
        nome=nome,
        tipo=tipo,
        criticidade=criticidade,
        armazena_dados_lgpd=armazena_lgpd,
    )


def criar_vinculo_acesso(colaborador, sistema, conta="usuario.vpn", status=VinculoAcesso.StatusAcesso.ATIVO):
    """Cria vínculo de acesso para um colaborador em um sistema."""
    return VinculoAcesso.objects.create(
        colaborador=colaborador,
        sistema=sistema,
        identificador_conta=conta,
        status=status,
    )


def criar_processo_offboarding(
    colaborador, responsavel_ti, status=ProcessoOffboarding.StatusOffboarding.INICIADO, motivo="Desligamento Formal"
):
    """Cria registro de processo de offboarding."""
    return ProcessoOffboarding.objects.create(
        colaborador=colaborador,
        responsavel_ti=responsavel_ti,
        status=status,
        observacoes=motivo,
    )


def criar_item_checklist(processo, vinculo, status=ItemChecklistOffboarding.StatusItem.PENDENTE):
    """Cria item do checklist de offboarding."""
    return ItemChecklistOffboarding.objects.create(
        processo=processo,
        vinculo_acesso=vinculo,
        status=status,
    )


def setup_fase10_fixtures(self):
    """Cria fixtures completas padrão para testes de integridade e deploy (Fase 10-12)."""
    from django.test import Client

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
    Authenticator.objects.create(user=self.superuser, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"})

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
    self.campanha = CampanhaRevisao.objects.create(
        nome="Campanha Teste Fixtures",
        prazo=timezone.localdate() + timezone.timedelta(days=30),
        criada_por=self.user_gestor,
        status=CampanhaRevisao.StatusCampanha.ABERTA,
    )
    self.item_revisao = ItemRevisao.objects.create(
        campanha=self.campanha,
        vinculo=self.vinculo,
        revisor=self.user_gestor,
        decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
    )
    self.solicitacao = SolicitacaoAcesso.objects.create(
        colaborador=self.colab,
        sistema=self.sis,
        identificador_conta="lucas.solic",
        justificativa="Acesso para desenvolvimento de testes no ambiente de CI",
        chamado="CHAMADO-001",
        status=SolicitacaoAcesso.StatusSolicitacao.PENDENTE_APROVACAO,
        solicitado_por=self.user_gestor,
    )
