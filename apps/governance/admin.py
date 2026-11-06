"""
Configuração do Django Admin para o Módulo de Governança & IAM (GateKeeper-DBF).

Painel voltado para analistas de SOC, SecOps e TI com filtros estratégicos
de criticidade, LGPD, status de colaborador e processo de offboarding.
Integrado ao simple_history para rastreamento de versões e imutabilidade de registros.
"""

from django.contrib import admin
from django.core.exceptions import PermissionDenied
from django.utils import timezone
from django.utils.html import format_html
from simple_history.admin import SimpleHistoryAdmin

from .models import (
    CampanhaRevisao,
    Cargo,
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    ItemRevisao,
    Localidade,
    PerfilAcesso,
    ProcessoOffboarding,
    Sistema,
    SolicitacaoAcesso,
    VinculoAcesso,
)

# Fase 9.1: selos e progresso por classe CSS (static/css/admin.css), sem style="".
# A CSP `style-src 'self'` bloqueia atributos style inline; classes mantêm a política rígida.
ADMIN_MEDIA_CSS = {"all": ("css/admin.css",)}


def _badge(rotulo, cor):
    """Selo colorido. `cor` vem sempre de um mapa fixo no código, nunca de dado do usuário."""
    return format_html('<span class="gk-badge gk-badge--{}">{}</span>', cor, rotulo)


class HistoricoSomenteLeituraAdmin(SimpleHistoryAdmin):
    """
    Histórico de versões apenas para consulta.

    No django-simple-history, a tela de uma versão antiga (history_form_view) exige só permissão
    de *leitura* e, num POST, grava o formulário recebido. Um Auditor conseguia assim alterar
    qualquer registro, inclusive os de offboarding bloqueados pelo SomenteLeituraAdminMixin.
    Reverter versões também contornaria a máquina de estados do services.py, por isso é negado a todos.
    Todo admin com histórico deve herdar desta classe (garantido por teste).
    """

    def history_form_view(self, request, object_id, version_id, extra_context=None):
        if request.method != "GET":
            raise PermissionDenied("O histórico é somente leitura: reverter versões não é permitido.")
        return super().history_form_view(request, object_id, version_id, extra_context)

    def revert_disabled(self, request, obj=None):
        return True


@admin.register(Localidade)
class LocalidadeAdmin(admin.ModelAdmin):
    list_display = ("nome", "codigo", "cidade", "estado", "ativo", "criado_em")
    list_filter = ("ativo", "estado")
    search_fields = ("nome", "codigo", "cidade")
    ordering = ("nome",)


@admin.register(Departamento)
class DepartamentoAdmin(admin.ModelAdmin):
    list_display = ("nome", "sigla", "ativo", "criado_em")
    list_filter = ("ativo",)
    search_fields = ("nome", "sigla")
    ordering = ("nome",)


@admin.register(Cargo)
class CargoAdmin(admin.ModelAdmin):
    list_display = ("nome", "departamento", "ativo", "criado_em")
    list_filter = ("ativo", "departamento")
    search_fields = ("nome", "departamento__nome", "departamento__sigla")
    filter_horizontal = ("perfis_padrao",)
    ordering = ("departamento__nome", "nome")


class PerfilAcessoInline(admin.TabularInline):
    model = PerfilAcesso
    extra = 1
    fields = ("nome", "nivel_privilegio", "descricao")


@admin.register(Sistema)
class SistemaAdmin(HistoricoSomenteLeituraAdmin):
    class Media:
        css = ADMIN_MEDIA_CSS

    list_display = (
        "nome",
        "tipo",
        "exibir_criticidade",
        "armazena_dados_lgpd",
        "tipo_autenticacao",
        "acesso_externo",
        "gestor_responsavel",
        "ativo",
    )
    list_filter = ("ativo", "criticidade", "tipo", "armazena_dados_lgpd", "tipo_autenticacao", "acesso_externo")
    search_fields = ("nome", "gestor_responsavel", "instrucoes_revogacao")
    inlines = [PerfilAcessoInline]

    @admin.display(description="Criticidade")
    def exibir_criticidade(self, obj):
        cores = {
            Sistema.Criticidade.CRITICA: "vermelho",
            Sistema.Criticidade.ALTA: "laranja",
            Sistema.Criticidade.MEDIA: "ambar",
            Sistema.Criticidade.BAIXA: "verde",
        }
        cor = cores.get(obj.criticidade, "neutro")
        return _badge(obj.get_criticidade_display(), cor)


@admin.register(PerfilAcesso)
class PerfilAcessoAdmin(admin.ModelAdmin):
    list_display = ("nome", "sistema", "nivel_privilegio", "criado_em")
    list_filter = ("nivel_privilegio", "sistema")
    search_fields = ("nome", "sistema__nome", "descricao")


class SomenteLeituraAdminMixin:
    """
    Fase 10.1: Registros de offboarding só mudam pelo services.py (máquina de estados + travas + logs).
    Bloqueia adições, alterações e exclusões via Django Admin para todos os usuários (inclusive superusuários).
    """

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class VinculoAcessoInline(SomenteLeituraAdminMixin, admin.TabularInline):
    """
    Somente consulta: concessão e alteração de vínculos passam pelo VinculoAcessoAdmin, que registra
    o operador (save_model) e trava vínculos revogados. Editar aqui contornaria as duas regras.
    """

    model = VinculoAcesso
    extra = 0
    fields = ("sistema", "perfil_acesso", "identificador_conta", "status", "data_concessao")
    show_change_link = True


@admin.register(Colaborador)
class ColaboradorAdmin(HistoricoSomenteLeituraAdmin):
    class Media:
        css = ADMIN_MEDIA_CSS

    list_display = (
        "nome_completo",
        "matricula",
        "email_corporativo",
        "departamento",
        "cargo",
        "localidade",
        "exibir_status",
        "total_acessos_ativos",
    )
    list_filter = ("status", "departamento", "localidade", "cargo")
    search_fields = ("nome_completo", "matricula", "email_corporativo", "email_pessoal")
    inlines = [VinculoAcessoInline]
    date_hierarchy = "data_admissao"

    # Fase 1.1: Imutabilidade - Registros de colaboradores nunca são excluídos do sistema
    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="Status")
    def exibir_status(self, obj):
        cores = {
            Colaborador.StatusColaborador.ATIVO: "verde",
            Colaborador.StatusColaborador.FERIAS: "azul",
            Colaborador.StatusColaborador.AFASTADO: "ambar",
            Colaborador.StatusColaborador.DESLIGADO: "vermelho",
        }
        cor = cores.get(obj.status, "neutro")
        return _badge(obj.get_status_display(), cor)


@admin.register(VinculoAcesso)
class VinculoAcessoAdmin(HistoricoSomenteLeituraAdmin):
    class Media:
        css = ADMIN_MEDIA_CSS

    list_display = (
        "colaborador",
        "sistema",
        "perfil_acesso",
        "identificador_conta",
        "exibir_status",
        "data_concessao",
        "data_revogacao",
    )
    list_filter = ("status", "sistema", "colaborador__departamento")
    search_fields = ("colaborador__nome_completo", "identificador_conta", "sistema__nome", "justificativa")
    autocomplete_fields = ("colaborador",)
    readonly_fields = ("concedido_por", "revogado_por", "data_concessao", "data_revogacao")

    # Fase 1.1 / 10.1: Imutabilidade da trilha e não-repúdio do operador
    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        # Revogação é estado final: reativar acesso de desligado exige um novo vínculo (nova concessão auditada).
        if obj is not None and obj.status == VinculoAcesso.StatusAcesso.REVOGADO:
            return False
        return super().has_change_permission(request, obj)

    def save_model(self, request, obj, form, change):
        if not change:
            if not obj.concedido_por:
                obj.concedido_por = request.user
            if not obj.data_concessao:
                obj.data_concessao = timezone.now()
        else:
            if obj.status == VinculoAcesso.StatusAcesso.REVOGADO:
                if not obj.revogado_por:
                    obj.revogado_por = request.user
                if not obj.data_revogacao:
                    obj.data_revogacao = timezone.now()
        super().save_model(request, obj, form, change)

    @admin.display(description="Status")
    def exibir_status(self, obj):
        cores = {
            VinculoAcesso.StatusAcesso.ATIVO: "verde",
            VinculoAcesso.StatusAcesso.REVOGADO: "vermelho",
            VinculoAcesso.StatusAcesso.BLOQUEADO: "ambar",
        }
        cor = cores.get(obj.status, "neutro")
        return _badge(obj.get_status_display(), cor)


class ItemChecklistOffboardingInline(SomenteLeituraAdminMixin, admin.TabularInline):
    model = ItemChecklistOffboarding
    extra = 0
    fields = ("vinculo_acesso", "status", "revogado", "data_revogacao", "responsavel_revogacao", "evidencia_revogacao")


@admin.register(ProcessoOffboarding)
class ProcessoOffboardingAdmin(SomenteLeituraAdminMixin, HistoricoSomenteLeituraAdmin):
    class Media:
        css = ADMIN_MEDIA_CSS

    list_display = ("colaborador", "exibir_progresso", "exibir_status", "responsavel_ti", "iniciado_em", "concluido_em")
    list_filter = ("status", "responsavel_ti")
    search_fields = ("colaborador__nome_completo", "observacoes")
    inlines = [ItemChecklistOffboardingInline]

    @admin.display(description="Progresso")
    def exibir_progresso(self, obj):
        pct = obj.percentual_concluido
        classe = "gk-admin-progress gk-admin-progress--done" if pct == 100 else "gk-admin-progress"
        return format_html(
            '<progress class="{}" value="{}" max="100" aria-label="{}%"></progress>'
            '<span class="gk-admin-progress-label">{}% ({}/{})</span>',
            classe,
            pct,
            pct,
            pct,
            obj.total_revogados,
            obj.total_itens,
        )

    @admin.display(description="Status")
    def exibir_status(self, obj):
        cores = {
            ProcessoOffboarding.StatusOffboarding.CONCLUIDO: "verde",
            ProcessoOffboarding.StatusOffboarding.INICIADO: "azul",
            ProcessoOffboarding.StatusOffboarding.PENDENTE: "vermelho",
        }
        cor = cores.get(obj.status, "neutro")
        return _badge(obj.get_status_display(), cor)


@admin.register(ItemChecklistOffboarding)
class ItemChecklistOffboardingAdmin(SomenteLeituraAdminMixin, HistoricoSomenteLeituraAdmin):
    list_display = ("processo", "vinculo_acesso", "status", "revogado", "data_revogacao", "responsavel_revogacao")
    list_filter = ("status", "revogado")
    search_fields = ("processo__colaborador__nome_completo", "vinculo_acesso__sistema__nome", "evidencia_revogacao")


class ItemRevisaoInline(SomenteLeituraAdminMixin, admin.TabularInline):
    model = ItemRevisao
    extra = 0
    fields = ("vinculo", "revisor", "decisao", "justificativa", "decidido_em", "tarefa_revogada")
    readonly_fields = fields


@admin.register(CampanhaRevisao)
class CampanhaRevisaoAdmin(SomenteLeituraAdminMixin, HistoricoSomenteLeituraAdmin):
    class Media:
        css = ADMIN_MEDIA_CSS

    list_display = (
        "nome",
        "exibir_status",
        "exibir_progresso",
        "prazo",
        "aberta_em",
        "criada_por",
    )
    list_filter = ("status", "escopo_criticidade_minima")
    search_fields = ("nome", "descricao")
    inlines = [ItemRevisaoInline]

    @admin.display(description="Progresso")
    def exibir_progresso(self, obj):
        pct = obj.percentual_concluido
        classe = "gk-admin-progress gk-admin-progress--done" if pct == 100 else "gk-admin-progress"
        return format_html(
            '<progress class="{}" value="{}" max="100" aria-label="{}%"></progress>'
            '<span class="gk-admin-progress-label">{}% ({}/{})</span>',
            classe,
            pct,
            pct,
            pct,
            obj.total_decididos,
            obj.total_itens,
        )

    @admin.display(description="Status")
    def exibir_status(self, obj):
        cores = {
            CampanhaRevisao.StatusCampanha.ABERTA: "azul",
            CampanhaRevisao.StatusCampanha.ENCERRADA: "verde",
        }
        cor = cores.get(obj.status, "neutro")
        return _badge(obj.get_status_display(), cor)


@admin.register(ItemRevisao)
class ItemRevisaoAdmin(SomenteLeituraAdminMixin, HistoricoSomenteLeituraAdmin):
    list_display = (
        "campanha",
        "vinculo",
        "revisor",
        "exibir_decisao",
        "decidido_em",
        "tarefa_revogada",
    )
    list_filter = ("decisao", "tarefa_revogada", "campanha")
    search_fields = (
        "campanha__nome",
        "vinculo__colaborador__nome_completo",
        "vinculo__sistema__nome",
        "revisor__username",
    )

    @admin.display(description="Decisão")
    def exibir_decisao(self, obj):
        cores = {
            ItemRevisao.DecisaoRevisao.MANTER: "verde",
            ItemRevisao.DecisaoRevisao.REVOGAR: "vermelho",
            ItemRevisao.DecisaoRevisao.PENDENTE: "ambar",
        }
        cor = cores.get(obj.decisao, "neutro")
        return _badge(obj.get_decisao_display(), cor)


@admin.register(SolicitacaoAcesso)
class SolicitacaoAcessoAdmin(SomenteLeituraAdminMixin, HistoricoSomenteLeituraAdmin):
    class Media:
        css = ADMIN_MEDIA_CSS

    list_display = (
        "id",
        "colaborador",
        "sistema",
        "perfil_acesso",
        "exibir_status",
        "solicitado_por",
        "solicitado_em",
        "aprovado_por",
        "concedido_por",
    )
    list_filter = ("status", "sistema")
    search_fields = ("colaborador__nome_completo", "sistema__nome", "chamado", "identificador_conta")

    @admin.display(description="Status")
    def exibir_status(self, obj):
        cores = {
            SolicitacaoAcesso.StatusSolicitacao.CONCEDIDO: "verde",
            SolicitacaoAcesso.StatusSolicitacao.APROVADO: "azul",
            SolicitacaoAcesso.StatusSolicitacao.PENDENTE_APROVACAO: "ambar",
            SolicitacaoAcesso.StatusSolicitacao.REJEITADO: "vermelho",
        }
        cor = cores.get(obj.status, "neutro")
        return _badge(obj.get_status_display(), cor)
