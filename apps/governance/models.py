"""
Modelos de Dados para o GateKeeper-DBF (Módulo de Governança & IAM).

Estruturado segundo boas práticas de segurança, rastreabilidade e compliance:
- CIS Controls v8 (Controle 5 - Account Management)
- MITRE ATT&CK: Prevenção a T1078 (Valid Accounts / Contas Órfãs)
- LGPD (Lei 13.709/2018 - Art. 46: Auditoria de Acessos e Proteção de Dados)
- Fase 1: Integridade da Auditoria, Imutabilidade (PROTECT) e Histórico de Alterações
"""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords


class Localidade(models.Model):
    """Filiais, sedes ou unidades remotas da organização."""

    nome = models.CharField(max_length=100, unique=True, verbose_name="Nome da Unidade/Filial")
    codigo = models.CharField(
        max_length=20, unique=True, verbose_name="Código da Filial", help_text="Ex: SP-MATRIZ, RJ-01, REMOTO"
    )
    cidade = models.CharField(max_length=100, verbose_name="Cidade")
    estado = models.CharField(max_length=2, verbose_name="UF")
    ativo = models.BooleanField(default=True, verbose_name="Ativo")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    class Meta:
        verbose_name = "Localidade / Filial"
        verbose_name_plural = "Localidades / Filiais"
        ordering = ["nome"]

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
        ordering = ["nome"]

    def __str__(self):
        return f"{self.nome} ({self.sigla})"


class Cargo(models.Model):
    """Cargos ou funções formais dos colaboradores."""

    nome = models.CharField(max_length=100, verbose_name="Título do Cargo")
    departamento = models.ForeignKey(
        Departamento, on_delete=models.PROTECT, related_name="cargos", verbose_name="Departamento Vinculado"
    )
    descricao = models.TextField(blank=True, verbose_name="Atribuições e Responsabilidades")
    ativo = models.BooleanField(default=True, verbose_name="Ativo")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    class Meta:
        verbose_name = "Cargo / Função"
        verbose_name_plural = "Cargos / Funções"
        unique_together = ("nome", "departamento")
        ordering = ["departamento__nome", "nome"]

    def __str__(self):
        return f"{self.nome} - {self.departamento.sigla}"


class Sistema(models.Model):
    """
    Inventário de Sistemas, Softwares, Bancos e Ativos de Rede da empresa.
    Classificados por criticidade, tipo de acesso e impacto LGPD.
    """

    class TipoSistema(models.TextChoices):
        SAAS = "SAAS", "SaaS / Nuvem"
        ONPREM = "ONPREM", "On-Premise / Servidor Local"
        VPN = "VPN", "VPN / Acesso Remoto"
        NETWORK = "NETWORK", "Rede / Firewall / MikroTik"
        DATABASE = "DATABASE", "Banco de Dados"
        PASTA_REDE = "PASTA_REDE", "Compartilhamento de Arquivos / SMB"
        OUTRO = "OUTRO", "Outro Ativo"

    class Criticidade(models.TextChoices):
        BAIXA = "BAIXA", "Baixa"
        MEDIA = "MEDIA", "Média"
        ALTA = "ALTA", "Alta"
        CRITICA = "CRITICA", "Crítica (Missão Crítica)"

    class TipoAutenticacao(models.TextChoices):
        INDIVIDUAL = "INDIVIDUAL", "Individual (E-mail Corporativo)"
        SSO_AD = "SSO_AD", "Integrado com Active Directory / SSO"
        COMPARTILHADO = "COMPARTILHADO", "Conta Genérica / Compartilhada (⚠️ Atenção)"

    class AcessoExterno(models.TextChoices):
        INTERNET = "INTERNET", "Acessível diretamente via Internet"
        SOMENTE_VPN = "SOMENTE_VPN", "Restrito via VPN Corporativa"
        REDE_LOCAL = "REDE_LOCAL", "Apenas Fisicamente na Rede Local"

    nome = models.CharField(max_length=150, unique=True, verbose_name="Nome do Sistema / Ativo")
    tipo = models.CharField(
        max_length=20, choices=TipoSistema.choices, default=TipoSistema.SAAS, verbose_name="Tipo de Ativo"
    )
    criticidade = models.CharField(
        max_length=15, choices=Criticidade.choices, default=Criticidade.MEDIA, verbose_name="Nível de Criticidade"
    )
    armazena_dados_lgpd = models.BooleanField(
        default=False,
        verbose_name="Armazena Dados Pessoais / LGPD",
        help_text="Marque se contém dados de clientes, funcionários, CPF, dados bancários, etc.",
    )
    tipo_autenticacao = models.CharField(
        max_length=20,
        choices=TipoAutenticacao.choices,
        default=TipoAutenticacao.INDIVIDUAL,
        verbose_name="Forma de Autenticação",
    )
    acesso_externo = models.CharField(
        max_length=20, choices=AcessoExterno.choices, default=AcessoExterno.INTERNET, verbose_name="Exposição de Rede"
    )
    gestor_responsavel = models.CharField(
        max_length=150,
        verbose_name="Responsável pela Gestão de Contas",
        help_text="Ex: TI Interna, Líder do Setor ou Suporte do Fornecedor",
    )
    dono = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sistemas_sob_responsabilidade",
        verbose_name="Dono do sistema (revisor)",
    )
    link_painel_admin = models.URLField(blank=True, verbose_name="URL de Acesso / Painel Admin")
    instrucoes_revogacao = models.TextField(
        blank=True,
        verbose_name="Instruções de Revogação (Playbook Offboarding)",
        help_text="Procedimento operacional para bloquear ou excluir contas neste ativo durante o desligamento.",
    )
    ativo = models.BooleanField(default=True, verbose_name="Ativo")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    # Auditoria de Alterações (Fase 1.2)
    history = HistoricalRecords()

    class Meta:
        verbose_name = "Sistema / Ativo Corporativo"
        verbose_name_plural = "Sistemas / Ativos Corporativos"
        ordering = ["nome"]

    def __str__(self):
        return f"{self.nome} [{self.get_tipo_display()}] - Criticidade {self.get_criticidade_display()}"

    @property
    def total_perfis(self):
        """Retorna o total de perfis mapeados (utiliza anotação _total_perfis para evitar consulta N+1)."""
        if hasattr(self, "_total_perfis"):
            return self._total_perfis
        return self.perfis.count()


class PerfilAcesso(models.Model):
    """Níveis de privilégio ou perfis específicos dentro de um sistema."""

    class NivelPrivilegio(models.TextChoices):
        LEITURA = "LEITURA", "Apenas Leitura / Consulta"
        OPERADOR = "OPERADOR", "Operador / Lançamento / Edição"
        SUPERVISOR = "SUPERVISOR", "Supervisor / Aprovação"
        ADMIN = "ADMIN", "Administrador / Acesso Privilegiado"

    sistema = models.ForeignKey(Sistema, on_delete=models.CASCADE, related_name="perfis", verbose_name="Sistema")
    nome = models.CharField(max_length=100, verbose_name="Nome do Perfil")
    nivel_privilegio = models.CharField(
        max_length=20,
        choices=NivelPrivilegio.choices,
        default=NivelPrivilegio.OPERADOR,
        verbose_name="Nível de Privilégio",
    )
    descricao = models.TextField(blank=True, verbose_name="Descrição das Permissões")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")

    class Meta:
        verbose_name = "Perfil de Acesso"
        verbose_name_plural = "Perfis de Acesso"
        unique_together = ("sistema", "nome")
        ordering = ["sistema__nome", "nome"]

    def __str__(self):
        return f"{self.sistema.nome} -> {self.nome} ({self.get_nivel_privilegio_display()})"


class Colaborador(models.Model):
    """
    Registro central do colaborador (Fonte Única da Verdade para TI e Segurança).
    """

    class StatusColaborador(models.TextChoices):
        ATIVO = "ATIVO", "Ativo"
        FERIAS = "FERIAS", "Em Férias"
        AFASTADO = "AFASTADO", "Afastado / Licença Médica"
        DESLIGADO = "DESLIGADO", "Desligado (Offboarding Executado)"

    nome_completo = models.CharField(max_length=200, verbose_name="Nome Completo")
    matricula = models.CharField(max_length=50, unique=True, blank=True, null=True, verbose_name="Matrícula / ID RH")
    email_corporativo = models.EmailField(unique=True, verbose_name="E-mail Corporativo")
    email_pessoal = models.EmailField(blank=True, verbose_name="E-mail Pessoal (Contato de Emergência)")
    telefone = models.CharField(max_length=30, blank=True, verbose_name="Telefone / Ramal")
    localidade = models.ForeignKey(
        Localidade, on_delete=models.PROTECT, related_name="colaboradores", verbose_name="Filial / Lotação"
    )
    departamento = models.ForeignKey(
        Departamento, on_delete=models.PROTECT, related_name="colaboradores", verbose_name="Departamento"
    )
    cargo = models.ForeignKey(
        Cargo, on_delete=models.PROTECT, related_name="colaboradores", verbose_name="Cargo / Função"
    )
    gestor_imediato = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="liderados",
        verbose_name="Gestor Imediato",
    )
    usuario = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="colaborador",
        verbose_name="Usuário no GateKeeper",
    )
    status = models.CharField(
        max_length=20,
        choices=StatusColaborador.choices,
        default=StatusColaborador.ATIVO,
        verbose_name="Status Operacional",
    )
    data_admissao = models.DateField(verbose_name="Data de Admissão")
    data_desligamento = models.DateField(null=True, blank=True, verbose_name="Data de Desligamento")
    observacoes = models.TextField(blank=True, verbose_name="Observações Gerais de TI")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Cadastrado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    # Auditoria de Alterações (Fase 1.2)
    history = HistoricalRecords()

    class Meta:
        verbose_name = "Colaborador"
        verbose_name_plural = "Colaboradores"
        ordering = ["nome_completo"]

    def __str__(self):
        return f"{self.nome_completo} ({self.cargo.nome} - {self.departamento.sigla}) [{self.get_status_display()}]"

    @property
    def total_acessos_ativos(self):
        """Retorna o total de acessos atualmente ativos concedidos a este colaborador (utiliza _total_acessos_ativos se anotado)."""
        if hasattr(self, "_total_acessos_ativos"):
            return self._total_acessos_ativos
        return self.vinculos_acesso.filter(status=VinculoAcesso.StatusAcesso.ATIVO).count()

    @property
    def processo_offboarding(self):
        """Retorna o processo de offboarding ativo ou o mais recente (compatibilidade de templates)."""
        return (
            self.processos_offboarding.filter(
                status__in=[
                    ProcessoOffboarding.StatusOffboarding.INICIADO,
                    ProcessoOffboarding.StatusOffboarding.PENDENTE,
                ]
            ).first()
            or self.processos_offboarding.order_by("-iniciado_em").first()
        )


class VinculoAcesso(models.Model):
    """
    Matriz de Acessos: Registro granular de qual credencial/acesso pertence a quem.
    Garante trilha de auditoria: quem concedeu, quando concedeu, quem revogou e quando revogou.
    Protegido contra exclusão acidental (on_delete=models.PROTECT).
    """

    class StatusAcesso(models.TextChoices):
        ATIVO = "ATIVO", "Ativo"
        REVOGADO = "REVOGADO", "Revogado"
        BLOQUEADO = "BLOQUEADO", "Bloqueado Temporariamente"

    colaborador = models.ForeignKey(
        Colaborador,
        on_delete=models.PROTECT,  # Fase 1.1: Proteção de integridade no banco
        related_name="vinculos_acesso",
        verbose_name="Colaborador",
    )
    sistema = models.ForeignKey(
        Sistema, on_delete=models.PROTECT, related_name="vinculos", verbose_name="Sistema / Ativo"
    )
    perfil_acesso = models.ForeignKey(
        PerfilAcesso,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="vinculos",
        verbose_name="Perfil / Privilégio",
    )
    identificador_conta = models.CharField(
        max_length=150,
        verbose_name="Usuário / Conta no Sistema",
        help_text="Login exato utilizado pelo colaborador neste sistema (ex: david.silva ou david@empresa.com.br)",
    )
    status = models.CharField(
        max_length=20, choices=StatusAcesso.choices, default=StatusAcesso.ATIVO, verbose_name="Status do Acesso"
    )
    data_concessao = models.DateTimeField(default=timezone.now, verbose_name="Data de Concessão")
    concedido_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="acessos_concedidos",
        verbose_name="Concedido por (TI)",
    )
    data_revogacao = models.DateTimeField(null=True, blank=True, verbose_name="Data de Revogação")
    revogado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="acessos_revogados",
        verbose_name="Revogado por (TI)",
    )
    justificativa = models.TextField(blank=True, verbose_name="Justificativa / Chamado de Acesso")
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name="Criado em")
    atualizado_em = models.DateTimeField(auto_now=True, verbose_name="Atualizado em")

    # Auditoria de Alterações (Fase 1.2)
    history = HistoricalRecords()

    class Meta:
        verbose_name = "Vínculo de Acesso (Matriz RBAC)"
        verbose_name_plural = "Vínculos de Acesso (Matriz RBAC)"
        unique_together = ("colaborador", "sistema", "identificador_conta")
        ordering = ["colaborador__nome_completo", "sistema__nome"]

    def __str__(self):
        return f"{self.colaborador.nome_completo} -> {self.sistema.nome} ({self.identificador_conta}) [{self.get_status_display()}]"

    def clean(self):
        """Validação de segurança: Bloqueia concessão de novos acessos a colaboradores desligados ou em offboarding."""
        super().clean()
        if self.colaborador_id and self.status == self.StatusAcesso.ATIVO:
            if self.colaborador.status == Colaborador.StatusColaborador.DESLIGADO:
                raise ValidationError("Não é permitido conceder novos acessos a um colaborador já desligado.")
            if hasattr(self.colaborador, "processos_offboarding"):
                em_andamento = self.colaborador.processos_offboarding.filter(
                    status__in=[
                        ProcessoOffboarding.StatusOffboarding.INICIADO,
                        ProcessoOffboarding.StatusOffboarding.PENDENTE,
                    ]
                ).exists()
                if em_andamento:
                    raise ValidationError(
                        "Não é permitido conceder novos acessos a um colaborador em processo de offboarding."
                    )

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


class ProcessoOffboarding(models.Model):
    """
    Registro formal de Desligamento e Revogação de Acessos.
    Atende aos requisitos de auditoria do CIS Controls v8 (5.5) e LGPD.
    Suporta recontratações históricas com ForeignKey e UniqueConstraint para processos ativos.
    """

    class StatusOffboarding(models.TextChoices):
        INICIADO = "INICIADO", "Iniciado / Em Andamento"
        CONCLUIDO = "CONCLUIDO", "Concluído (100% dos Acessos Revogados)"
        PENDENTE = "PENDENTE", "Pendente / Bloqueado com Erro de Revogação"

    colaborador = models.ForeignKey(
        Colaborador,
        on_delete=models.PROTECT,  # Fase 1.1: Proteção de integridade no banco
        related_name="processos_offboarding",
        verbose_name="Colaborador Desligado",
    )
    status = models.CharField(
        max_length=20,
        choices=StatusOffboarding.choices,
        default=StatusOffboarding.INICIADO,
        verbose_name="Status do Processo",
    )
    iniciado_em = models.DateTimeField(auto_now_add=True, verbose_name="Iniciado em")
    concluido_em = models.DateTimeField(null=True, blank=True, verbose_name="Concluído em")
    responsavel_ti = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="offboardings_executados",
        verbose_name="Analista de TI Responsável",
    )
    observacoes = models.TextField(blank=True, verbose_name="Observações de Encerramento")

    # Auditoria de Alterações (Fase 1.2)
    history = HistoricalRecords()

    class Meta:
        verbose_name = "Processo de Offboarding"
        verbose_name_plural = "Processos de Offboarding"
        ordering = ["-iniciado_em"]
        permissions = [
            ("iniciar_offboarding", "Pode iniciar processo de offboarding"),
            ("revogar_item_offboarding", "Pode revogar item do checklist de offboarding"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["colaborador"],
                condition=~models.Q(status="CONCLUIDO"),
                name="unique_active_offboarding_per_colaborador",
            )
        ]

    def __str__(self):
        return f"Offboarding: {self.colaborador.nome_completo} [{self.get_status_display()}]"

    @property
    def total_itens(self):
        if hasattr(self, "_total_itens"):
            return self._total_itens
        return self.itens_checklist.count()

    @property
    def total_revogados(self):
        if hasattr(self, "_total_revogados"):
            return self._total_revogados
        return self.itens_checklist.filter(status=ItemChecklistOffboarding.StatusItem.REVOGADO).count()

    @property
    def total_resolvidos(self):
        """Itens que já não representam pendência ativa (Revogados, Falhas registradas ou Não Aplicáveis)."""
        if hasattr(self, "_total_resolvidos"):
            return self._total_resolvidos
        return self.itens_checklist.exclude(status=ItemChecklistOffboarding.StatusItem.PENDENTE).count()

    @property
    def percentual_concluido(self):
        total = self.total_itens
        if total == 0:
            return 100
        return int((self.total_resolvidos / total) * 100)


class ItemChecklistOffboarding(models.Model):
    """
    Item individual do checklist de revogação por sistema para um colaborador em desligamento.
    """

    class StatusItem(models.TextChoices):
        PENDENTE = "PENDENTE", "Pendente"
        REVOGADO = "REVOGADO", "Revogado com Sucesso"
        FALHA = "FALHA", "Falha / Bloqueado com Erro"
        NAO_APLICAVEL = "NAO_APLICAVEL", "Não Aplicável"

    processo = models.ForeignKey(
        ProcessoOffboarding,
        on_delete=models.CASCADE,
        related_name="itens_checklist",
        verbose_name="Processo de Offboarding",
    )
    vinculo_acesso = models.ForeignKey(
        VinculoAcesso,
        on_delete=models.PROTECT,  # Fase 1.1: Proteção de integridade no banco
        related_name="itens_offboarding",
        verbose_name="Acesso a ser Revogado",
    )
    status = models.CharField(
        max_length=20, choices=StatusItem.choices, default=StatusItem.PENDENTE, verbose_name="Status da Revogação"
    )
    revogado = models.BooleanField(default=False, verbose_name="Acesso Revogado com Sucesso?")
    data_revogacao = models.DateTimeField(null=True, blank=True, verbose_name="Data/Hora da Revogação")
    responsavel_revogacao = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Revogado por"
    )
    evidencia_revogacao = models.TextField(
        blank=True,
        verbose_name="Evidência / ID de Chamado / Log",
        help_text="Código do ticket de suporte, ID do chamado ou log que comprova a exclusão/bloqueio da conta.",
    )
    observacao = models.TextField(blank=True, verbose_name="Observações Técnicas")

    # Auditoria de Alterações (Fase 1.2)
    history = HistoricalRecords()

    class Meta:
        verbose_name = "Item de Checklist de Offboarding"
        verbose_name_plural = "Itens de Checklist de Offboarding"
        ordering = ["processo", "vinculo_acesso__sistema__nome"]
        permissions = [
            ("marcar_nao_aplicavel", "Pode marcar item de checklist como Não Aplicável"),
        ]

    def __str__(self):
        return f"[{self.get_status_display()}] {self.vinculo_acesso.sistema.nome} ({self.vinculo_acesso.identificador_conta})"


class CampanhaRevisao(models.Model):
    """
    Fase 15.1: Ciclo de Revisão Periódica de Acessos (Recertificação).
    Tira uma fotografia auditável dos acessos ativos para validação pelos gestores/donos.
    """

    class StatusCampanha(models.TextChoices):
        ABERTA = "ABERTA", "Aberta"
        ENCERRADA = "ENCERRADA", "Encerrada"

    nome = models.CharField(max_length=150, verbose_name="Nome da Campanha")
    descricao = models.TextField(blank=True, verbose_name="Descrição do Escopo")
    escopo_criticidade_minima = models.CharField(
        max_length=15,
        choices=Sistema.Criticidade.choices,
        blank=True,
        null=True,
        verbose_name="Criticidade Mínima do Escopo",
        help_text="Se informado, apenas sistemas com esta criticidade ou superior entram na campanha",
    )
    escopo_departamentos = models.ManyToManyField(
        Departamento,
        blank=True,
        related_name="campanhas_revisao",
        verbose_name="Departamentos no Escopo",
        help_text="Se vazio, abrange todos os departamentos",
    )
    aberta_em = models.DateTimeField(default=timezone.now, verbose_name="Aberta em")
    prazo = models.DateField(verbose_name="Prazo de Conclusão")
    encerrada_em = models.DateTimeField(null=True, blank=True, verbose_name="Encerrada em")
    status = models.CharField(
        max_length=20,
        choices=StatusCampanha.choices,
        default=StatusCampanha.ABERTA,
        verbose_name="Status da Campanha",
    )
    criada_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="campanhas_revisao_criadas",
        verbose_name="Criada por (SecOps)",
    )
    history = HistoricalRecords()

    class Meta:
        verbose_name = "Campanha de Revisão"
        verbose_name_plural = "Campanhas de Revisão"
        ordering = ["-aberta_em"]
        permissions = [
            ("abrir_campanha_revisao", "Pode abrir e encerrar campanhas de revisão de acessos"),
        ]

    def __str__(self):
        return f"{self.nome} [{self.get_status_display()}]"

    @property
    def total_itens(self):
        if hasattr(self, "_total_itens"):
            return self._total_itens
        return self.itens.count()

    @property
    def total_decididos(self):
        if hasattr(self, "_total_decididos"):
            return self._total_decididos
        return self.itens.exclude(decisao=ItemRevisao.DecisaoRevisao.PENDENTE).count()

    @property
    def total_revogados(self):
        if hasattr(self, "_total_revogados"):
            return self._total_revogados
        return self.itens.filter(decisao=ItemRevisao.DecisaoRevisao.REVOGAR).count()

    @property
    def total_mantidos(self):
        if hasattr(self, "_total_mantidos"):
            return self._total_mantidos
        return self.itens.filter(decisao=ItemRevisao.DecisaoRevisao.MANTER).count()

    @property
    def total_pendentes(self):
        if hasattr(self, "_total_pendentes"):
            return self._total_pendentes
        return self.itens.filter(decisao=ItemRevisao.DecisaoRevisao.PENDENTE).count()

    @property
    def percentual_concluido(self):
        total = self.total_itens
        if total == 0:
            return 100
        return int((self.total_decididos / total) * 100)

    @property
    def esta_vencida(self):
        return self.status == self.StatusCampanha.ABERTA and timezone.localdate() > self.prazo


class ItemRevisao(models.Model):
    """
    Fase 15.1: Item individual de revisão de um vínculo de acesso específico.
    Protegido por segregação de funções, auditoria e rastreabilidade total.
    """

    class DecisaoRevisao(models.TextChoices):
        PENDENTE = "PENDENTE", "Pendente"
        MANTER = "MANTER", "Manter Acesso"
        REVOGAR = "REVOGAR", "Revogar Acesso"

    campanha = models.ForeignKey(
        CampanhaRevisao,
        on_delete=models.PROTECT,
        related_name="itens",
        verbose_name="Campanha de Revisão",
    )
    vinculo = models.ForeignKey(
        VinculoAcesso,
        on_delete=models.PROTECT,
        related_name="itens_revisao",
        verbose_name="Vínculo de Acesso",
    )
    revisor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="revisoes_atribuidas",
        verbose_name="Revisor Designado",
    )
    decisao = models.CharField(
        max_length=20,
        choices=DecisaoRevisao.choices,
        default=DecisaoRevisao.PENDENTE,
        verbose_name="Decisão do Revisor",
    )
    justificativa = models.TextField(
        blank=True,
        verbose_name="Justificativa da Decisão",
        help_text="Obrigatória (mín. 20 caracteres) para REVOGAR e para MANTER em sistema CRÍTICO",
    )
    decidido_em = models.DateTimeField(null=True, blank=True, verbose_name="Decidido em")
    decidido_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="revisoes_decididas",
        verbose_name="Decidido por",
    )

    # Fase 15.3: Revogação decorrente executada pela TI
    tarefa_revogada = models.BooleanField(
        default=False,
        verbose_name="Revogação Executada pela TI?",
        help_text="Indica se a equipe técnica executou a revogação no sistema de origem",
    )
    executado_em = models.DateTimeField(null=True, blank=True, verbose_name="Data/Hora da Revogação Técnica")
    executado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revisoes_executadas_ti",
        verbose_name="Executado por (TI)",
    )
    evidencia_revogacao = models.CharField(
        max_length=255,
        blank=True,
        verbose_name="Evidência da Revogação (TI)",
        help_text="Número do ticket, chamado ou identificador de auditoria comprovando a remoção",
    )
    history = HistoricalRecords()

    class Meta:
        verbose_name = "Item de Revisão"
        verbose_name_plural = "Itens de Revisão"
        ordering = ["campanha", "vinculo"]
        constraints = [models.UniqueConstraint(fields=["campanha", "vinculo"], name="unique_campanha_vinculo_revisao")]
        permissions = [
            ("revisar_acesso", "Pode revisar acessos atribuídos a si"),
        ]

    def __str__(self):
        return f"{self.campanha.nome} - {self.vinculo.colaborador.nome_completo} ({self.vinculo.sistema.nome}) [{self.get_decisao_display()}]"
