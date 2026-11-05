"""
Configuração do Django Admin para o Módulo de Governança & IAM (GateKeeper-DBF).

Painel voltado para analistas de SOC, SecOps e TI com filtros estratégicos
de criticidade, LGPD, status de colaborador e processo de offboarding.
Integrado ao simple_history para rastreamento de versões e imutabilidade de registros.
"""

from django.contrib import admin
from django.utils import timezone
from django.utils.html import format_html
from simple_history.admin import SimpleHistoryAdmin

from .models import (
    Cargo,
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    Localidade,
    PerfilAcesso,
    ProcessoOffboarding,
    Sistema,
    VinculoAcesso,
)

# Fase 9.1: selos e progresso por classe CSS (static/css/admin.css), sem style="".
# A CSP `style-src 'self'` bloqueia atributos style inline; classes mantêm a política rígida.
ADMIN_MEDIA_CSS = {"all": ("css/admin.css",)}


def _badge(rotulo, cor):
    """Selo colorido. `cor` vem sempre de um mapa fixo no código, nunca de dado do usuário."""
    return format_html('<span class="gk-badge gk-badge--{}">{}</span>', cor, rotulo)


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
    ordering = ("departamento__nome", "nome")


class PerfilAcessoInline(admin.TabularInline):
    model = PerfilAcesso
    extra = 1
    fields = ("nome", "nivel_privilegio", "descricao")


@admin.register(Sistema)
class SistemaAdmin(SimpleHistoryAdmin):
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


class VinculoAcessoInline(admin.TabularInline):
    model = VinculoAcesso
    extra = 0
    fields = ("sistema", "perfil_acesso", "identificador_conta", "status", "data_concessao")
    readonly_fields = ("data_concessao",)


@admin.register(Colaborador)
class ColaboradorAdmin(SimpleHistoryAdmin):
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
class VinculoAcessoAdmin(SimpleHistoryAdmin):
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


class ItemChecklistOffboardingInline(SomenteLeituraAdminMixin, admin.TabularInline):
    model = ItemChecklistOffboarding
    extra = 0
    fields = ("vinculo_acesso", "status", "revogado", "data_revogacao", "responsavel_revogacao", "evidencia_revogacao")


@admin.register(ProcessoOffboarding)
class ProcessoOffboardingAdmin(SomenteLeituraAdminMixin, SimpleHistoryAdmin):
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
class ItemChecklistOffboardingAdmin(SomenteLeituraAdminMixin, SimpleHistoryAdmin):
    list_display = ("processo", "vinculo_acesso", "status", "revogado", "data_revogacao", "responsavel_revogacao")
    list_filter = ("status", "revogado")
    search_fields = ("processo__colaborador__nome_completo", "vinculo_acesso__sistema__nome", "evidencia_revogacao")
