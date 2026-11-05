"""
Modelos de Dados para o GateKeeper-DBF (Módulo de Governança & IAM).

Estruturado segundo boas práticas de segurança, rastreabilidade e compliance:
- CIS Controls v8 (Controle 5 - Account Management)
- MITRE ATT&CK: Prevenção a T1078 (Valid Accounts / Contas Órfãs)
- LGPD (Lei 13.709/2018 - Art. 46: Auditoria de Acessos e Proteção de Dados)
"""

from django.db import models
from django.conf import settings
from django.utils import timezone


class Localidade(models.Model):
    """Filiais, sedes ou unidades remotas da organização."""
    nome = models.CharField(max_length=100, unique=True, verbose_name="Nome da Unidade/Filial")
    codigo = models.CharField(max_length=20, unique=True, verbose_name="Código da Filial", help_text="Ex: SP-MATRIZ, RJ-01, REMOTO")
    cidade = models.CharField(max_length=100, verbose_name="Cidade")
    estado = models.CharField(max_length=2, verbose_name="UF")
    ativo = models.BooleanField(default=True, verbose_name="Ativo")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    class Meta:
        verbose_name = "Localidade / Filial"
        verbose_name_plural = "Localidades / Filiais"
        ordering = ['nome']

    def __str__(self):
        return f"{self.nome} ({self.codigo})"


class Departamento(models.Model):
    """Departamentos ou setores corporativos (ex: Financeiro, TI, RH)."""
    nome = models.CharField(max_length=100, unique=True, verbose_name="Nome do Setor")
    sigla = models.CharField(max_length=10, unique=True, verbose_name="Sigla", help_text="Ex: FIN, TI, RH, LOG")
    descricao = models.TextField(blank=True, verbose_name="Descrição das Atividades")
    ativo = models.BooleanField(default=True, verbose_name="Ativo")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    class Meta:
        verbose_name = "Departamento / Setor"
        verbose_name_plural = "Departamentos / Setores"
        ordering = ['nome']

    def __str__(self):
        return f"{self.nome} ({self.sigla})"


class Cargo(models.Model):
    """Cargos ou funções formais dos colaboradores."""
    nome = models.CharField(max_length=100, verbose_name="Título do Cargo")
    departamento = models.ForeignKey(
        Departamento,
        on_delete=models.PROTECT,
        related_name='cargos',
        verbose_name="Departamento Vinculado"
    )
    descricao = models.TextField(blank=True, verbose_name="Atribuições e Responsabilidades")
    ativo = models.BooleanField(default=True, verbose_name="Ativo")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    class Meta:
        verbose_name = "Cargo / Função"
        verbose_name_plural = "Cargos / Funções"
        unique_together = ('nome', 'departamento')
        ordering = ['departamento__nome', 'nome']

    def __str__(self):
        return f"{self.nome} - {self.departamento.sigla}"


class Sistema(models.Model):
    """
    Inventário de Sistemas, Softwares, Bancos e Ativos de Rede da empresa.
    Classificados por criticidade, tipo de acesso e impacto LGPD.
    """
    class TipoSistema(models.TextChoices):
        SAAS = 'SAAS', 'SaaS / Nuvem'
        ONPREM = 'ONPREM', 'On-Premise / Servidor Local'
        VPN = 'VPN', 'VPN / Acesso Remoto'
        NETWORK = 'NETWORK', 'Rede / Firewall / MikroTik'
        DATABASE = 'DATABASE', 'Banco de Dados'
        PASTA_REDE = 'PASTA_REDE', 'Compartilhamento de Arquivos / SMB'
        OUTRO = 'OUTRO', 'Outro Ativo'

    class Criticidade(models.TextChoices):
        BAIXA = 'BAIXA', 'Baixa'
        MEDIA = 'MEDIA', 'Média'
        ALTA = 'ALTA', 'Alta'
        CRITICA = 'CRITICA', 'Crítica (Missão Crítica)'

    class TipoAutenticacao(models.TextChoices):
        INDIVIDUAL = 'INDIVIDUAL', 'Individual (E-mail Corporativo)'
        SSO_AD = 'SSO_AD', 'Integrado com Active Directory / SSO'
        COMPARTILHADO = 'COMPARTILHADO', 'Conta Genérica / Compartilhada (⚠️ Atenção)'

    class AcessoExterno(models.TextChoices):
        INTERNET = 'INTERNET', 'Acessível diretamente via Internet'
        SOMENTE_VPN = 'SOMENTE_VPN', 'Restrito via VPN Corporativa'
        REDE_LOCAL = 'REDE_LOCAL', 'Apenas Fisicamente na Rede Local'

    nome = models.CharField(max_length=150, unique=True, verbose_name="Nome do Sistema / Ativo")
    tipo = models.CharField(max_length=20, choices=TipoSistema.choices, default=TipoSistema.SAAS, verbose_name="Tipo de Ativo")
    criticidade = models.CharField(max_length=15, choices=Criticidade.choices, default=Criticidade.MEDIA, verbose_name="Nível de Criticidade")
    armazena_dados_lgpd = models.BooleanField(default=False, verbose_name="Armazena Dados Pessoais / LGPD", help_text="Marque se contém dados de clientes, funcionários, CPF, dados bancários, etc.")
    tipo_autenticacao = models.CharField(max_length=20, choices=TipoAutenticacao.choices, default=TipoAutenticacao.INDIVIDUAL, verbose_name="Forma de Autenticação")
    acesso_externo = models.CharField(max_length=20, choices=AcessoExterno.choices, default=AcessoExterno.INTERNET, verbose_name="Exposição de Rede")
    gestor_responsavel = models.CharField(max_length=150, verbose_name="Responsável pela Gestão de Contas", help_text="Ex: TI Interna, Líder do Setor ou Suporte do Fornecedor")
    link_painel_admin = models.URLField(blank=True, verbose_name="URL de Acesso / Painel Admin")
    instrucoes_revogacao = models.TextField(
        blank=True,
        verbose_name="Instruções de Revogação (Playbook Offboarding)",
        help_text="Procedimento operacional para bloquear ou excluir contas neste ativo durante o desligamento."
    )
    ativo = models.BooleanField(default=True, verbose_name="Ativo")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    class Meta:
        verbose_name = "Sistema / Ativo Corporativo"
        verbose_name_plural = "Sistemas / Ativos Corporativos"
        ordering = ['nome']

    def __str__(self):
        return f"{self.nome} [{self.get_tipo_display()}] - Criticidade {self.get_criticidade_display()}"


class PerfilAcesso(models.Model):
    """Níveis de privilégio ou perfis específicos dentro de um sistema."""
    class NivelPrivilegio(models.TextChoices):
        LEITURA = 'LEITURA', 'Apenas Leitura / Consulta'
        OPERADOR = 'OPERADOR', 'Operador / Lançamento / Edição'
        SUPERVISOR = 'SUPERVISOR', 'Supervisor / Aprovação'
        ADMIN = 'ADMIN', 'Administrador / Acesso Privilegiado'

    sistema = models.ForeignKey(Sistema, on_delete=models.CASCADE, related_name='perfis', verbose_name="Sistema")
    nome = models.CharField(max_length=100, verbose_name="Nome do Perfil")
    nivel_privilegio = models.CharField(
        max_length=20,
        choices=NivelPrivilegio.choices,
        default=NivelPrivilegio.OPERADOR,
        verbose_name="Nível de Privilégio"
    )
    descricao = models.TextField(blank=True, verbose_name="Descrição das Permissões")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")

    class Meta:
        verbose_name = "Perfil de Acesso"
        verbose_name_plural = "Perfis de Acesso"
        unique_together = ('sistema', 'nome')
        ordering = ['sistema__nome', 'nome']

    def __str__(self):
        return f"{self.sistema.nome} -> {self.nome} ({self.get_nivel_privilegio_display()})"


class Colaborador(models.Model):
    """
    Registro central do colaborador (Fonte Única da Verdade para TI e Segurança).
    """
    class StatusColaborador(models.TextChoices):
        ATIVO = 'ATIVO', 'Ativo'
        FERIAS = 'FERIAS', 'Em Férias'
        AFASTADO = 'AFASTADO', 'Afastado / Licença Médica'
        DESLIGADO = 'DESLIGADO', 'Desligado (Offboarding Executado)'

    nome_completo = models.CharField(max_length=200, verbose_name="Nome Completo")
    matricula = models.CharField(max_length=50, unique=True, blank=True, null=True, verbose_name="Matrícula / ID RH")
    email_corporativo = models.EmailField(unique=True, verbose_name="E-mail Corporativo")
    email_pessoal = models.EmailField(blank=True, verbose_name="E-mail Pessoal (Contato de Emergência)")
    telefone = models.CharField(max_length=30, blank=True, verbose_name="Telefone / Ramal")
    localidade = models.ForeignKey(Localidade, on_delete=models.PROTECT, related_name='colaboradores', verbose_name="Filial / Lotação")
    departamento = models.ForeignKey(Departamento, on_delete=models.PROTECT, related_name='colaboradores', verbose_name="Departamento")
    cargo = models.ForeignKey(Cargo, on_delete=models.PROTECT, related_name='colaboradores', verbose_name="Cargo / Função")
    gestor_imediato = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='liderados',
        verbose_name="Gestor Imediato"
    )
    status = models.CharField(
        max_length=20,
        choices=StatusColaborador.choices,
        default=StatusColaborador.ATIVO,
        verbose_name="Status Operacional"
    )
    data_admissao = models.DateField(verbose_name="Data de Admissão")
    data_desligamento = models.DateField(null=True, blank=True, verbose_name="Data de Desligamento")
    observacoes = models.TextField(blank=True, verbose_name="Observações Gerais de TI")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Cadastrado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    class Meta:
        verbose_name = "Colaborador"
        verbose_name_plural = "Colaboradores"
        ordering = ['nome_completo']

    def __str__(self):
        return f"{self.nome_completo} ({self.cargo.nome} - {self.departamento.sigla}) [{self.get_status_display()}]"

    @property
    def total_acessos_ativos(self):
        """Retorna o total de acessos atualmente ativos concedidos a este colaborador."""
        return self.vinculos_acesso.filter(status=VinculoAcesso.StatusAcesso.ATIVO).count()


class VinculoAcesso(models.Model):
    """
    Matriz de Acessos: Registro granular de qual credencial/acesso pertence a quem.
    Garante trilha de auditoria: quem concedeu, quando concedeu, quem revogou e quando revogou.
    """
    class StatusAcesso(models.TextChoices):
        ATIVO = 'ATIVO', 'Ativo'
        REVOGADO = 'REVOGADO', 'Revogado'
        BLOQUEADO = 'BLOQUEADO', 'Bloqueado Temporariamente'

    colaborador = models.ForeignKey(
        Colaborador,
        on_delete=models.CASCADE,
        related_name='vinculos_acesso',
        verbose_name="Colaborador"
    )
    sistema = models.ForeignKey(
        Sistema,
        on_delete=models.PROTECT,
        related_name='vinculos',
        verbose_name="Sistema / Ativo"
    )
    perfil_acesso = models.ForeignKey(
        PerfilAcesso,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='vinculos',
        verbose_name="Perfil / Privilégio"
    )
    identificador_conta = models.CharField(
        max_length=150,
        verbose_name="Usuário / Conta no Sistema",
        help_text="Login exato utilizado pelo colaborador neste sistema (ex: david.silva ou david@empresa.com.br)"
    )
    status = models.CharField(
        max_length=20,
        choices=StatusAcesso.choices,
        default=StatusAcesso.ATIVO,
        verbose_name="Status do Acesso"
    )
    data_concessao = models.DateTimeField(default=timezone.now, verbose_name="Data de Concessão")
    concedido_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='acessos_concedidos',
        verbose_name="Concedido por (TI)"
    )
    data_revogacao = models.DateTimeField(null=True, blank=True, verbose_name="Data de Revogação")
    revogado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='acessos_revogados',
        verbose_name="Revogado por (TI)"
    )
    justificativa = models.TextField(blank=True, verbose_name="Justificativa / Chamado de Acesso")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    class Meta:
        verbose_name = "Vínculo de Acesso (Matriz RBAC)"
        verbose_name_plural = "Vínculos de Acesso (Matriz RBAC)"
        unique_together = ('colaborador', 'sistema', 'identificador_conta')
        ordering = ['colaborador__nome_completo', 'sistema__nome']

    def __str__(self):
        return f"{self.colaborador.nome_completo} -> {self.sistema.nome} ({self.identificador_conta}) [{self.get_status_display()}]"


class ProcessoOffboarding(models.Model):
    """
    Registro formal de Desligamento e Revogação de Acessos.
    Atende aos requisitos de auditoria do CIS Controls v8 (5.5) e LGPD.
    """
    class StatusOffboarding(models.TextChoices):
        INICIADO = 'INICIADO', 'Iniciado / Em Andamento'
        CONCLUIDO = 'CONCLUIDO', 'Concluído (100% dos Acessos Revogados)'
        PENDENTE = 'PENDENTE', 'Pendente / Bloqueado com Erro de Revogação'

    colaborador = models.OneToOneField(
        Colaborador,
        on_delete=models.CASCADE,
        related_name='processo_offboarding',
        verbose_name="Colaborador Desligado"
    )
    status = models.CharField(
        max_length=20,
        choices=StatusOffboarding.choices,
        default=StatusOffboarding.INICIADO,
        verbose_name="Status do Processo"
    )
    iniciado_em = models.DateTimeField(auto_now_add=True, verbose_name="Iniciado em")
    concluido_em = models.DateTimeField(null=True, blank=True, verbose_name="Concluído em")
    responsavel_ti = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='offboardings_executados',
        verbose_name="Analista de TI Responsável"
    )
    observacoes = models.TextField(blank=True, verbose_name="Observações de Encerramento")

    class Meta:
        verbose_name = "Processo de Offboarding"
        verbose_name_plural = "Processos de Offboarding"
        ordering = ['-iniciado_em']

    def __str__(self):
        return f"Offboarding: {self.colaborador.nome_completo} [{self.get_status_display()}]"

    @property
    def total_itens(self):
        return self.itens_checklist.count()

    @property
    def total_revogados(self):
        return self.itens_checklist.filter(revogado=True).count()

    @property
    def percentual_concluido(self):
        total = self.total_itens
        if total == 0:
            return 100
        return int((self.total_revogados / total) * 100)


class ItemChecklistOffboarding(models.Model):
    """
    Item individual do checklist de revogação por sistema para um colaborador em desligamento.
    """
    processo = models.ForeignKey(
        ProcessoOffboarding,
        on_delete=models.CASCADE,
        related_name='itens_checklist',
        verbose_name="Processo de Offboarding"
    )
    vinculo_acesso = models.ForeignKey(
        VinculoAcesso,
        on_delete=models.CASCADE,
        related_name='itens_offboarding',
        verbose_name="Acesso a ser Revogado"
    )
    revogado = models.BooleanField(default=False, verbose_name="Acesso Revogado com Sucesso?")
    data_revogacao = models.DateTimeField(null=True, blank=True, verbose_name="Data/Hora da Revogação")
    responsavel_revogacao = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="Revogado por"
    )
    evidencia_revogacao = models.TextField(
        blank=True,
        verbose_name="Evidência / ID de Chamado / Log",
        help_text="Código do ticket de suporte, ID do chamado ou log que comprova a exclusão/bloqueio da conta."
    )
    observacao = models.TextField(blank=True, verbose_name="Observações Técnicas")

    class Meta:
        verbose_name = "Item de Checklist de Offboarding"
        verbose_name_plural = "Itens de Checklist de Offboarding"
        ordering = ['processo', 'vinculo_acesso__sistema__nome']

    def __str__(self):
        status_txt = "REVOGADO" if self.revogado else "PENDENTE"
        return f"[{status_txt}] {self.vinculo_acesso.sistema.nome} ({self.vinculo_acesso.identificador_conta})"
