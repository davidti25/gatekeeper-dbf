"""
Views para a Interface Web do GateKeeper-DBF.

Contempla:
- Dashboard Executivo com Alertas de Risco SOC (MITRE ATT&CK T1078)
- Gestão de Colaboradores e Inventário de Sistemas
- Matriz RBAC de Acessos Concedidos
- Central Guiada de Offboarding & Checklist com Auditoria (CIS 5.5 / LGPD)
- Segregação de Funções e RBAC Nativo (Fase 0 - Emergência)
"""

import logging

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import ValidationError
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.generic import DetailView, ListView, TemplateView

from .forms import RevogacaoItemForm
from .models import (
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    ProcessoOffboarding,
    Sistema,
    VinculoAcesso,
)
from .services import iniciar_offboarding, revogar_item_checklist

logger = logging.getLogger("gatekeeper.audit")

User = get_user_model()


class DashboardView(PermissionRequiredMixin, TemplateView):
    """
    Dashboard Executivo com segregação de funções e controle de acesso estrito (Fase 5.2).
    Acessível para todos os perfis autorizados (Auditor, Analista TI, Gestor SecOps).
    """

    permission_required = "governance.view_colaborador"
    template_name = "governance/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Contadores Principais (KPIs)
        context["total_colaboradores"] = Colaborador.objects.count()
        context["colaboradores_ativos"] = Colaborador.objects.filter(status=Colaborador.StatusColaborador.ATIVO).count()
        context["total_sistemas"] = Sistema.objects.filter(ativo=True).count()
        context["sistemas_criticos"] = Sistema.objects.filter(
            criticidade=Sistema.Criticidade.CRITICA, ativo=True
        ).count()
        context["sistemas_lgpd"] = Sistema.objects.filter(armazena_dados_lgpd=True, ativo=True).count()
        context["acessos_ativos"] = VinculoAcesso.objects.filter(status=VinculoAcesso.StatusAcesso.ATIVO).count()

        # KPIs de Offboarding
        context["offboardings_em_andamento"] = ProcessoOffboarding.objects.filter(
            status=ProcessoOffboarding.StatusOffboarding.INICIADO
        ).count()
        context["offboardings_concluidos"] = ProcessoOffboarding.objects.filter(
            status=ProcessoOffboarding.StatusOffboarding.CONCLUIDO
        ).count()

        # Alertas de Risco de Segurança (SOC / Threat Hunting)
        # 1. Contas Órfãs Críticas: Colaborador com status DESLIGADO, mas ainda com acessos ATIVOS
        contas_orfas_qs = VinculoAcesso.objects.filter(
            colaborador__status=Colaborador.StatusColaborador.DESLIGADO, status=VinculoAcesso.StatusAcesso.ATIVO
        ).select_related("colaborador", "sistema")
        context["contas_orfas_risco"] = contas_orfas_qs
        context["total_contas_orfas"] = contas_orfas_qs.count()

        # 2. Sistemas com Autenticação Compartilhada (Ponto de Vulnerabilidade)
        context["sistemas_compartilhados"] = Sistema.objects.filter(
            tipo_autenticacao=Sistema.TipoAutenticacao.COMPARTILHADO, ativo=True
        )

        # Últimos Processos de Offboarding (Otimizado sem N+1)
        context["ultimos_offboardings"] = (
            ProcessoOffboarding.objects.select_related("colaborador", "responsavel_ti")
            .annotate(
                _total_itens=Count("itens_checklist", distinct=True),
                _total_revogados=Count(
                    "itens_checklist",
                    filter=Q(itens_checklist__status=ItemChecklistOffboarding.StatusItem.REVOGADO),
                    distinct=True,
                ),
                _total_resolvidos=Count(
                    "itens_checklist",
                    filter=~Q(itens_checklist__status=ItemChecklistOffboarding.StatusItem.PENDENTE),
                    distinct=True,
                ),
            )
            .order_by("-iniciado_em")[:5]
        )

        # Resumo por Departamento
        context["departamentos_resumo"] = Departamento.objects.annotate(
            total_colaboradores=Count("colaboradores"),
            ativos=Count("colaboradores", filter=Q(colaboradores__status=Colaborador.StatusColaborador.ATIVO)),
        ).order_by("-total_colaboradores")

        return context


class ColaboradorListView(PermissionRequiredMixin, ListView):
    model = Colaborador
    template_name = "governance/colaborador_list.html"
    context_object_name = "colaboradores"
    permission_required = "governance.view_colaborador"
    paginate_by = 15

    def get_queryset(self):
        qs = Colaborador.objects.select_related("departamento", "cargo", "localidade").annotate(
            _total_acessos_ativos=Count(
                "vinculos_acesso", filter=Q(vinculos_acesso__status=VinculoAcesso.StatusAcesso.ATIVO), distinct=True
            )
        )
        q = self.request.GET.get("q")
        status = self.request.GET.get("status")
        depto = self.request.GET.get("departamento")

        if q:
            qs = qs.filter(
                Q(nome_completo__icontains=q) | Q(email_corporativo__icontains=q) | Q(matricula__icontains=q)
            )
        if status:
            qs = qs.filter(status=status)
        if depto:
            qs = qs.filter(departamento__id=depto)

        return qs.order_by("nome_completo")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["departamentos"] = Departamento.objects.filter(ativo=True)
        context["status_choices"] = Colaborador.StatusColaborador.choices
        context["current_q"] = self.request.GET.get("q", "")
        context["current_status"] = self.request.GET.get("status", "")
        context["current_depto"] = self.request.GET.get("departamento", "")
        return context


class ColaboradorDetailView(PermissionRequiredMixin, DetailView):
    model = Colaborador
    template_name = "governance/colaborador_detail.html"
    context_object_name = "colaborador"
    permission_required = "governance.view_colaborador"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        colab = self.object
        context["acessos_ativos"] = colab.vinculos_acesso.filter(
            status=VinculoAcesso.StatusAcesso.ATIVO
        ).select_related("sistema", "perfil_acesso")
        context["acessos_revogados"] = colab.vinculos_acesso.filter(
            status=VinculoAcesso.StatusAcesso.REVOGADO
        ).select_related("sistema", "perfil_acesso", "revogado_por")
        context["offboarding"] = getattr(colab, "processo_offboarding", None)
        return context


@permission_required("governance.iniciar_offboarding", raise_exception=True)
def iniciar_offboarding_view(request, pk):
    """
    Inicia o fluxo formal de offboarding para um colaborador via serviço atômico (Fase 6.3).
    Exige permissão estrita 'governance.iniciar_offboarding' (Analista TI / Gestor SecOps).
    Garante não-repúdio absoluto: o responsável é estritamente request.user.
    """
    if request.method != "POST":
        return redirect("colaborador_detail", pk=pk)

    motivo = request.POST.get("motivo_desligamento", "Desligamento Formal")
    try:
        processo, criado = iniciar_offboarding(
            colaborador_id=pk,
            responsavel=request.user,
            motivo=motivo,
        )
    except Colaborador.DoesNotExist:
        messages.error(request, "Colaborador não encontrado.")
        return redirect("colaborador_list")
    except ValidationError as e:
        messages.error(request, str(e.message if hasattr(e, "message") else e))
        return redirect("colaborador_detail", pk=pk)

    if not criado:
        messages.warning(
            request,
            f"O colaborador {processo.colaborador.nome_completo} já possui um processo de offboarding em andamento.",
        )
        return redirect("offboarding_detail", pk=processo.pk)

    if processo.status == ProcessoOffboarding.StatusOffboarding.CONCLUIDO:
        messages.success(
            request, f"Offboarding de {processo.colaborador.nome_completo} concluído (não possuía acessos vinculados)."
        )
    else:
        messages.success(
            request,
            f"Processo de Offboarding iniciado para {processo.colaborador.nome_completo}. {processo.total_itens} acesso(s) pendente(s) de revogação.",
        )

    return redirect("offboarding_detail", pk=processo.pk)


class OffboardingListView(PermissionRequiredMixin, ListView):
    model = ProcessoOffboarding
    template_name = "governance/offboarding_list.html"
    context_object_name = "processos"
    permission_required = "governance.view_processooffboarding"
    paginate_by = 15

    def get_queryset(self):
        qs = ProcessoOffboarding.objects.select_related(
            "colaborador", "colaborador__cargo", "colaborador__departamento", "responsavel_ti"
        ).annotate(
            _total_itens=Count("itens_checklist", distinct=True),
            _total_revogados=Count(
                "itens_checklist",
                filter=Q(itens_checklist__status=ItemChecklistOffboarding.StatusItem.REVOGADO),
                distinct=True,
            ),
            _total_resolvidos=Count(
                "itens_checklist",
                filter=~Q(itens_checklist__status=ItemChecklistOffboarding.StatusItem.PENDENTE),
                distinct=True,
            ),
        )
        status = self.request.GET.get("status")
        if status:
            qs = qs.filter(status=status)
        return qs.order_by("-iniciado_em")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["status_choices"] = ProcessoOffboarding.StatusOffboarding.choices
        context["current_status"] = self.request.GET.get("status", "")
        return context


class OffboardingDetailView(PermissionRequiredMixin, DetailView):
    model = ProcessoOffboarding
    template_name = "governance/offboarding_detail.html"
    context_object_name = "processo"
    permission_required = "governance.view_processooffboarding"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        processo = self.object
        context["itens"] = processo.itens_checklist.select_related(
            "vinculo_acesso__sistema", "vinculo_acesso__perfil_acesso", "responsavel_revogacao"
        )
        return context


@permission_required("governance.revogar_item_offboarding", raise_exception=True)
def revogar_item_offboarding_view(request, pk, item_id):
    """
    Executa a revogação de um item específico do checklist de offboarding,
    validando evidência e executando serviço transacional atômico.
    Exige permissão estrita 'governance.revogar_item_offboarding'.
    Garante não-repúdio absoluto: responsavel = request.user.
    """
    if request.method != "POST":
        return redirect("offboarding_detail", pk=pk)

    processo = get_object_or_404(ProcessoOffboarding, pk=pk)
    item = get_object_or_404(ItemChecklistOffboarding, pk=item_id, processo=processo)

    form = RevogacaoItemForm(request.POST, item=item, user=request.user)
    if not form.is_valid():
        for errors in form.errors.values():
            for error in errors:
                messages.error(request, error)
        return redirect("offboarding_detail", pk=pk)

    cleaned_data = form.cleaned_data
    try:
        item, proc = revogar_item_checklist(
            item_id=item.pk,
            responsavel=request.user,
            evidencia=cleaned_data.get("evidencia_revogacao", ""),
            observacao=cleaned_data.get("observacao", ""),
            status=cleaned_data.get("status", ItemChecklistOffboarding.StatusItem.REVOGADO),
        )
        if proc.status == ProcessoOffboarding.StatusOffboarding.CONCLUIDO:
            messages.success(
                request,
                f"🎉 100% dos acessos de {proc.colaborador.nome_completo} foram resolvidos! Processo de Offboarding concluído com sucesso e auditado.",
            )
        elif proc.status == ProcessoOffboarding.StatusOffboarding.PENDENTE:
            messages.warning(
                request,
                f"⚠️ Item marcado como '{item.get_status_display()}'. O processo de offboarding possui pendências ou bloqueios a resolver.",
            )
        else:
            messages.success(
                request,
                f"Acesso ao sistema '{item.vinculo_acesso.sistema.nome}' ({item.vinculo_acesso.identificador_conta}) marcado como {item.get_status_display()}.",
            )
    except ValidationError as e:
        messages.error(request, str(e.message if hasattr(e, "message") else e))

    return redirect("offboarding_detail", pk=pk)


class OffboardingRelatorioView(PermissionRequiredMixin, DetailView):
    """
    Gera o Relatório Formal de Encerramento de Acessos para Auditoria e Compliance.
    Alinhado a CIS Controls v8 (Requisito 5.5) e LGPD Art. 46.
    """

    model = ProcessoOffboarding
    template_name = "governance/offboarding_relatorio.html"
    context_object_name = "processo"
    permission_required = "governance.view_processooffboarding"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        itens = self.object.itens_checklist.select_related(
            "vinculo_acesso__sistema", "vinculo_acesso__perfil_acesso", "responsavel_revogacao"
        )
        context["itens"] = itens
        context["gerado_em"] = timezone.now()
        # Fase 6.4: Invariante de integridade - verifica se há algum vínculo ativo neste processo
        context["inconsistente"] = self.object.itens_checklist.filter(
            vinculo_acesso__status=VinculoAcesso.StatusAcesso.ATIVO
        ).exists()
        return context


class SistemaListView(PermissionRequiredMixin, ListView):
    model = Sistema
    template_name = "governance/sistema_list.html"
    context_object_name = "sistemas"
    permission_required = "governance.view_sistema"
    paginate_by = 15

    def get_queryset(self):
        qs = Sistema.objects.filter(ativo=True).annotate(_total_perfis=Count("perfis", distinct=True))
        q = self.request.GET.get("q")
        criticidade = self.request.GET.get("criticidade")
        tipo = self.request.GET.get("tipo")
        lgpd = self.request.GET.get("lgpd")

        if q:
            qs = qs.filter(nome__icontains=q)
        if criticidade:
            qs = qs.filter(criticidade=criticidade)
        if tipo:
            qs = qs.filter(tipo=tipo)
        if lgpd:
            qs = qs.filter(armazena_dados_lgpd=(lgpd == "true"))

        return qs.order_by("nome")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["criticidades"] = Sistema.Criticidade.choices
        context["tipos"] = Sistema.TipoSistema.choices
        context["current_q"] = self.request.GET.get("q", "")
        context["current_criticidade"] = self.request.GET.get("criticidade", "")
        context["current_tipo"] = self.request.GET.get("tipo", "")
        context["current_lgpd"] = self.request.GET.get("lgpd", "")
        return context


class MatrizAcessoListView(PermissionRequiredMixin, ListView):
    model = VinculoAcesso
    template_name = "governance/matriz_acessos.html"
    context_object_name = "vinculos"
    permission_required = "governance.view_vinculoacesso"
    paginate_by = 20

    def get_queryset(self):
        qs = VinculoAcesso.objects.select_related(
            "colaborador", "colaborador__departamento", "colaborador__cargo", "sistema", "perfil_acesso"
        )
        q = self.request.GET.get("q")
        status = self.request.GET.get("status")
        sistema_id = self.request.GET.get("sistema")

        if q:
            qs = qs.filter(
                Q(colaborador__nome_completo__icontains=q)
                | Q(identificador_conta__icontains=q)
                | Q(sistema__nome__icontains=q)
            )
        if status:
            qs = qs.filter(status=status)
        if sistema_id:
            qs = qs.filter(sistema__id=sistema_id)

        return qs.order_by("-data_concessao")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["sistemas"] = Sistema.objects.filter(ativo=True)
        context["status_choices"] = VinculoAcesso.StatusAcesso.choices
        context["current_q"] = self.request.GET.get("q", "")
        context["current_status"] = self.request.GET.get("status", "")
        context["current_sistema"] = self.request.GET.get("sistema", "")
        return context
