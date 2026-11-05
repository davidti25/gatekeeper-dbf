"""
Views para a Interface Web do GateKeeper-DBF.

Contempla:
- Dashboard Executivo com Alertas de Risco SOC (MITRE ATT&CK T1078)
- Gestão de Colaboradores e Inventário de Sistemas
- Matriz RBAC de Acessos Concedidos
- Central Guiada de Offboarding & Checklist com Auditoria (CIS 5.5 / LGPD)
"""

from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic import TemplateView, ListView, DetailView
from django.contrib import messages
from django.utils import timezone
from django.db.models import Count, Q
from django.contrib.auth import get_user_model
from .models import (
    Colaborador,
    Sistema,
    PerfilAcesso,
    VinculoAcesso,
    ProcessoOffboarding,
    ItemChecklistOffboarding,
    Departamento,
    Localidade,
)

User = get_user_model()


class DashboardView(TemplateView):
    template_name = 'governance/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Contadores Principais (KPIs)
        context['total_colaboradores'] = Colaborador.objects.count()
        context['colaboradores_ativos'] = Colaborador.objects.filter(status=Colaborador.StatusColaborador.ATIVO).count()
        context['total_sistemas'] = Sistema.objects.filter(ativo=True).count()
        context['sistemas_criticos'] = Sistema.objects.filter(criticidade=Sistema.Criticidade.CRITICA, ativo=True).count()
        context['sistemas_lgpd'] = Sistema.objects.filter(armazena_dados_lgpd=True, ativo=True).count()
        context['acessos_ativos'] = VinculoAcesso.objects.filter(status=VinculoAcesso.StatusAcesso.ATIVO).count()

        # KPIs de Offboarding
        context['offboardings_em_andamento'] = ProcessoOffboarding.objects.filter(
            status=ProcessoOffboarding.StatusOffboarding.INICIADO
        ).count()
        context['offboardings_concluidos'] = ProcessoOffboarding.objects.filter(
            status=ProcessoOffboarding.StatusOffboarding.CONCLUIDO
        ).count()

        # Alertas de Risco de Segurança (SOC / Threat Hunting)
        # 1. Contas Órfãs Críticas: Colaborador com status DESLIGADO, mas ainda com acessos ATIVOS
        contas_orfas_qs = VinculoAcesso.objects.filter(
            colaborador__status=Colaborador.StatusColaborador.DESLIGADO,
            status=VinculoAcesso.StatusAcesso.ATIVO
        ).select_related('colaborador', 'sistema')
        context['contas_orfas_risco'] = contas_orfas_qs
        context['total_contas_orfas'] = contas_orfas_qs.count()

        # 2. Sistemas com Autenticação Compartilhada (Ponto de Vulnerabilidade)
        context['sistemas_compartilhados'] = Sistema.objects.filter(
            tipo_autenticacao=Sistema.TipoAutenticacao.COMPARTILHADO,
            ativo=True
        )

        # Últimos Processos de Offboarding
        context['ultimos_offboardings'] = ProcessoOffboarding.objects.select_related(
            'colaborador', 'responsavel_ti'
        ).order_by('-iniciado_em')[:5]

        # Resumo por Departamento
        context['departamentos_resumo'] = Departamento.objects.annotate(
            total_colaboradores=Count('colaboradores'),
            ativos=Count('colaboradores', filter=Q(colaboradores__status=Colaborador.StatusColaborador.ATIVO))
        ).order_by('-total_colaboradores')

        return context


class ColaboradorListView(ListView):
    model = Colaborador
    template_name = 'governance/colaborador_list.html'
    context_object_name = 'colaboradores'
    paginate_by = 15

    def get_queryset(self):
        qs = Colaborador.objects.select_related('departamento', 'cargo', 'localidade').prefetch_related('vinculos_acesso')
        q = self.request.GET.get('q')
        status = self.request.GET.get('status')
        depto = self.request.GET.get('departamento')

        if q:
            qs = qs.filter(
                Q(nome_completo__icontains=q) |
                Q(email_corporativo__icontains=q) |
                Q(matricula__icontains=q)
            )
        if status:
            qs = qs.filter(status=status)
        if depto:
            qs = qs.filter(departamento__id=depto)

        return qs.order_by('nome_completo')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['departamentos'] = Departamento.objects.filter(ativo=True)
        context['status_choices'] = Colaborador.StatusColaborador.choices
        context['current_q'] = self.request.GET.get('q', '')
        context['current_status'] = self.request.GET.get('status', '')
        context['current_depto'] = self.request.GET.get('departamento', '')
        return context


class ColaboradorDetailView(DetailView):
    model = Colaborador
    template_name = 'governance/colaborador_detail.html'
    context_object_name = 'colaborador'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        colab = self.object
        context['acessos_ativos'] = colab.vinculos_acesso.filter(
            status=VinculoAcesso.StatusAcesso.ATIVO
        ).select_related('sistema', 'perfil_acesso')
        context['acessos_revogados'] = colab.vinculos_acesso.filter(
            status=VinculoAcesso.StatusAcesso.REVOGADO
        ).select_related('sistema', 'perfil_acesso', 'revogado_por')
        context['offboarding'] = getattr(colab, 'processo_offboarding', None)
        return context


def iniciar_offboarding_view(request, pk):
    """
    Inicia o fluxo formal de offboarding para um colaborador.
    Gera automaticamente as pendências no checklist para cada acesso ativo.
    """
    if request.method != 'POST':
        return redirect('colaborador_detail', pk=pk)

    colaborador = get_object_or_404(Colaborador, pk=pk)

    # Evita duplicação do processo
    if hasattr(colaborador, 'processo_offboarding'):
        messages.warning(request, f"O colaborador {colaborador.nome_completo} já possui um processo de offboarding em andamento.")
        return redirect('offboarding_detail', pk=colaborador.processo_offboarding.pk)

    # Identifica o responsável técnico pela execução (ou fallback para primeiro admin)
    responsavel = request.user if request.user.is_authenticated else User.objects.filter(is_staff=True).first()
    if not responsavel:
        responsavel = User.objects.first()
        if not responsavel:
            responsavel = User.objects.create_user(
                username='analista.secops',
                email='secops@empresa.com.br',
                is_staff=True
            )

    # Cria o processo formal
    processo = ProcessoOffboarding.objects.create(
        colaborador=colaborador,
        responsavel_ti=responsavel,
        status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        observacoes=request.POST.get('motivo_desligamento', 'Desligamento Formal')
    )

    # Gera os itens do checklist para todos os acessos atualmente ativos
    acessos_ativos = colaborador.vinculos_acesso.filter(status=VinculoAcesso.StatusAcesso.ATIVO)
    for vinculo in acessos_ativos:
        ItemChecklistOffboarding.objects.create(
            processo=processo,
            vinculo_acesso=vinculo
        )

    # Se o colaborador não possuía nenhum acesso, conclui imediatamente
    if not acessos_ativos.exists():
        processo.status = ProcessoOffboarding.StatusOffboarding.CONCLUIDO
        processo.concluido_em = timezone.now()
        processo.save()
        colaborador.status = Colaborador.StatusColaborador.DESLIGADO
        colaborador.data_desligamento = timezone.now().date()
        colaborador.save()
        messages.success(request, f"Offboarding de {colaborador.nome_completo} concluído (não possuía acessos vinculados).")
    else:
        messages.success(request, f"Processo de Offboarding iniciado para {colaborador.nome_completo}. {acessos_ativos.count()} acessos pendentes de revogação.")

    return redirect('offboarding_detail', pk=processo.pk)


class OffboardingListView(ListView):
    model = ProcessoOffboarding
    template_name = 'governance/offboarding_list.html'
    context_object_name = 'processos'
    paginate_by = 15

    def get_queryset(self):
        qs = ProcessoOffboarding.objects.select_related(
            'colaborador', 'colaborador__cargo', 'colaborador__departamento', 'responsavel_ti'
        ).prefetch_related('itens_checklist')
        status = self.request.GET.get('status')
        if status:
            qs = qs.filter(status=status)
        return qs.order_by('-iniciado_em')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = ProcessoOffboarding.StatusOffboarding.choices
        context['current_status'] = self.request.GET.get('status', '')
        return context


class OffboardingDetailView(DetailView):
    model = ProcessoOffboarding
    template_name = 'governance/offboarding_detail.html'
    context_object_name = 'processo'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        processo = self.object
        context['itens'] = processo.itens_checklist.select_related(
            'vinculo_acesso__sistema',
            'vinculo_acesso__perfil_acesso',
            'responsavel_revogacao'
        )
        return context


def revogar_item_offboarding_view(request, pk, item_id):
    """
    Executa a revogação de um item específico do checklist de offboarding,
    registrando a evidência (ticket/chamado/log) e atualizando o status do vínculo.
    """
    if request.method != 'POST':
        return redirect('offboarding_detail', pk=pk)

    processo = get_object_or_404(ProcessoOffboarding, pk=pk)
    item = get_object_or_404(ItemChecklistOffboarding, pk=item_id, processo=processo)

    responsavel = request.user if request.user.is_authenticated else processo.responsavel_ti
    evidencia = request.POST.get('evidencia_revogacao', '').strip()
    observacao = request.POST.get('observacao', '').strip()

    # Atualiza o item do checklist
    agora = timezone.now()
    item.revogado = True
    item.data_revogacao = agora
    item.responsavel_revogacao = responsavel
    item.evidencia_revogacao = evidencia or 'Revogado manualmente via painel GateKeeper-DBF.'
    item.observacao = observacao
    item.save()

    # Atualiza o Vínculo de Acesso correspondente
    vinculo = item.vinculo_acesso
    vinculo.status = VinculoAcesso.StatusAcesso.REVOGADO
    vinculo.data_revogacao = agora
    vinculo.revogado_por = responsavel
    vinculo.justificativa = f"Offboarding executado. Evidência: {item.evidencia_revogacao}"
    vinculo.save()

    # Verifica se todos os itens foram concluídos
    if processo.total_itens > 0 and processo.total_revogados == processo.total_itens:
        processo.status = ProcessoOffboarding.StatusOffboarding.CONCLUIDO
        processo.concluido_em = agora
        processo.save()

        # Atualiza o Colaborador como formalmente desligado
        colab = processo.colaborador
        colab.status = Colaborador.StatusColaborador.DESLIGADO
        if not colab.data_desligamento:
            colab.data_desligamento = agora.date()
        colab.save()

        messages.success(request, f"🎉 100% dos acessos de {colab.nome_completo} foram revogados! Processo de Offboarding concluído com sucesso e auditado.")
    else:
        messages.success(request, f"Acesso ao sistema '{vinculo.sistema.nome}' ({vinculo.identificador_conta}) marcado como revogado.")

    return redirect('offboarding_detail', pk=pk)


class OffboardingRelatorioView(DetailView):
    """
    Gera o Relatório Formal de Encerramento de Acessos para Auditoria e Compliance.
    Alinhado a CIS Controls v8 (Requisito 5.5) e LGPD Art. 46.
    """
    model = ProcessoOffboarding
    template_name = 'governance/offboarding_relatorio.html'
    context_object_name = 'processo'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['itens'] = self.object.itens_checklist.select_related(
            'vinculo_acesso__sistema',
            'vinculo_acesso__perfil_acesso',
            'responsavel_revogacao'
        )
        context['gerado_em'] = timezone.now()
        return context


class SistemaListView(ListView):
    model = Sistema
    template_name = 'governance/sistema_list.html'
    context_object_name = 'sistemas'
    paginate_by = 15

    def get_queryset(self):
        qs = Sistema.objects.filter(ativo=True).prefetch_related('perfis')
        q = self.request.GET.get('q')
        criticidade = self.request.GET.get('criticidade')
        tipo = self.request.GET.get('tipo')
        lgpd = self.request.GET.get('lgpd')

        if q:
            qs = qs.filter(nome__icontains=q)
        if criticidade:
            qs = qs.filter(criticidade=criticidade)
        if tipo:
            qs = qs.filter(tipo=tipo)
        if lgpd:
            qs = qs.filter(armazena_dados_lgpd=(lgpd == 'true'))

        return qs.order_by('nome')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['criticidades'] = Sistema.Criticidade.choices
        context['tipos'] = Sistema.TipoSistema.choices
        context['current_q'] = self.request.GET.get('q', '')
        context['current_criticidade'] = self.request.GET.get('criticidade', '')
        context['current_tipo'] = self.request.GET.get('tipo', '')
        context['current_lgpd'] = self.request.GET.get('lgpd', '')
        return context


class MatrizAcessoListView(ListView):
    model = VinculoAcesso
    template_name = 'governance/matriz_acessos.html'
    context_object_name = 'vinculos'
    paginate_by = 20

    def get_queryset(self):
        qs = VinculoAcesso.objects.select_related(
            'colaborador', 'colaborador__departamento', 'colaborador__cargo', 'sistema', 'perfil_acesso'
        )
        q = self.request.GET.get('q')
        status = self.request.GET.get('status')
        sistema_id = self.request.GET.get('sistema')

        if q:
            qs = qs.filter(
                Q(colaborador__nome_completo__icontains=q) |
                Q(identificador_conta__icontains=q) |
                Q(sistema__nome__icontains=q)
            )
        if status:
            qs = qs.filter(status=status)
        if sistema_id:
            qs = qs.filter(sistema__id=sistema_id)

        return qs.order_by('-data_concessao')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['sistemas'] = Sistema.objects.filter(ativo=True)
        context['status_choices'] = VinculoAcesso.StatusAcesso.choices
        context['current_q'] = self.request.GET.get('q', '')
        context['current_status'] = self.request.GET.get('status', '')
        context['current_sistema'] = self.request.GET.get('sistema', '')
        return context
