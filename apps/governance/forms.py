"""
Formulários de Validação para Governança e Offboarding (GateKeeper-DBF).

Fase 1.4: Validação estrita de evidências em ativos críticos e escopo LGPD.
"""

from django import forms
from django.core.exceptions import ValidationError
from .models import ItemChecklistOffboarding, Sistema


class RevogacaoItemForm(forms.Form):
    status = forms.ChoiceField(
        choices=ItemChecklistOffboarding.StatusItem.choices,
        required=False,
        initial=ItemChecklistOffboarding.StatusItem.REVOGADO,
        widget=forms.Select(attrs={
            'class': 'w-full px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-white focus:outline-none focus:ring-1 focus:ring-sky-500'
        })
    )
    evidencia_revogacao = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'placeholder': 'Ex: Ticket GLPI #4582 / Conta desativada no AD',
            'class': 'w-full px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-sky-500'
        })
    )
    observacao = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'placeholder': 'Observações técnicas complementares',
            'class': 'w-full px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-sky-500'
        })
    )

    def __init__(self, *args, item=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.item = item

    def clean_status(self):
        status = self.cleaned_data.get('status')
        return status or ItemChecklistOffboarding.StatusItem.REVOGADO

    def clean_evidencia_revogacao(self):
        evidencia = self.cleaned_data.get('evidencia_revogacao', '').strip()

        if self.item:
            sistema = self.item.vinculo_acesso.sistema
            sensivel = (
                sistema.criticidade in [Sistema.Criticidade.CRITICA, Sistema.Criticidade.ALTA] or
                sistema.armazena_dados_lgpd
            )
            # Para sistemas críticos ou com dados pessoais (LGPD), a evidência é estritamente obrigatória
            if sensivel and not evidencia:
                raise ValidationError(
                    f"A evidência de revogação (ID do chamado, ticket GLPI ou log) é estritamente obrigatória "
                    f"para o sistema '{sistema.nome}', classificado com Criticidade {sistema.get_criticidade_display()} ou escopo LGPD."
                )

        # Rejeitar texto vago / genérico
        if evidencia.lower() in ['revogado manualmente', 'teste', 'ok', 'revogado']:
            raise ValidationError("Informe uma evidência válida (ex: número de ticket, código de chamado ou nota de auditoria).")

        return evidencia
