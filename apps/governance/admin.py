"""
Configuração do Django Admin para o Módulo de Governança & IAM (GateKeeper-DBF).

Painel voltado para analistas de SOC, SecOps e TI com filtros estratégicos
de criticidade, LGPD, status de colaborador e processo de offboarding.
Integrado ao simple_history para rastreamento de versões e imutabilidade de registros.
"""

from django.contrib import admin
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
            Sistema.Criticidade.CRITICA: "#b91c1c",
            Sistema.Criticidade.ALTA: "#ea580c",
            Sistema.Criticidade.MEDIA: "#ca8a04",
            Sistema.Criticidade.BAIXA: "#15803d",
        }
        cor = cores.get(obj.criticidade, "#4b5563")
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{}</span>',
            cor,
            obj.get_criticidade_display(),
        )


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
            Colaborador.StatusColaborador.ATIVO: "#15803d",
            Colaborador.StatusColaborador.FERIAS: "#0284c7",
            Colaborador.StatusColaborador.AFASTADO: "#d97706",
            Colaborador.StatusColaborador.DESLIGADO: "#dc2626",
        }
        cor = cores.get(obj.status, "#6b7280")
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{}</span>',
            cor,
            obj.get_status_display(),
        )


@admin.register(VinculoAcesso)
class VinculoAcessoAdmin(SimpleHistoryAdmin):
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

    # Fase 1.1: Imutabilidade da trilha de auditoria
    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="Status")
    def exibir_status(self, obj):
        cores = {
            VinculoAcesso.StatusAcesso.ATIVO: "#15803d",
            VinculoAcesso.StatusAcesso.REVOGADO: "#dc2626",
            VinculoAcesso.StatusAcesso.BLOQUEADO: "#d97706",
        }
        cor = cores.get(obj.status, "#6b7280")
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{}</span>',
            cor,
            obj.get_status_display(),
        )


class ItemChecklistOffboardingInline(admin.TabularInline):
    model = ItemChecklistOffboarding
    extra = 0
    fields = ("vinculo_acesso", "status", "revogado", "data_revogacao", "responsavel_revogacao", "evidencia_revogacao")


@admin.register(ProcessoOffboarding)
class ProcessoOffboardingAdmin(SimpleHistoryAdmin):
    list_display = ("colaborador", "exibir_progresso", "exibir_status", "responsavel_ti", "iniciado_em", "concluido_em")
    list_filter = ("status", "responsavel_ti")
    search_fields = ("colaborador__nome_completo", "observacoes")
    inlines = [ItemChecklistOffboardingInline]

    # Fase 1.1: Imutabilidade do processo de desligamento
    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="Progresso")
    def exibir_progresso(self, obj):
        pct = obj.percentual_concluido
        cor_barra = "#15803d" if pct == 100 else "#2563eb"
        return format_html(
            """
            <div style="width: 120px; background-color: #e5e7eb; border-radius: 4px; overflow: hidden; height: 16px; display: inline-block; vertical-align: middle;">
                <div style="width: {}%; background-color: {}; height: 100%;"></div>
            </div>
            <span style="font-weight: bold; margin-left: 6px; font-size: 11px;">{}% ({}/{})</span>
            """,
            pct,
            cor_barra,
            pct,
            obj.total_revogados,
            obj.total_itens,
        )

    @admin.display(description="Status")
    def exibir_status(self, obj):
        cores = {
            ProcessoOffboarding.StatusOffboarding.CONCLUIDO: "#15803d",
            ProcessoOffboarding.StatusOffboarding.INICIADO: "#0284c7",
            ProcessoOffboarding.StatusOffboarding.PENDENTE: "#dc2626",
        }
        cor = cores.get(obj.status, "#6b7280")
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{}</span>',
            cor,
            obj.get_status_display(),
        )


@admin.register(ItemChecklistOffboarding)
class ItemChecklistOffboardingAdmin(SimpleHistoryAdmin):
    list_display = ("processo", "vinculo_acesso", "status", "revogado", "data_revogacao", "responsavel_revogacao")
    list_filter = ("status", "revogado")
    search_fields = ("processo__colaborador__nome_completo", "vinculo_acesso__sistema__nome", "evidencia_revogacao")

    def has_delete_permission(self, request, obj=None):
        return False
