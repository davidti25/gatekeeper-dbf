"""
Formulários de Validação para Governança e Offboarding (GateKeeper-DBF).

Contempla:
- Fase 1.4: Validação estrita de evidências em ativos críticos e escopo LGPD.
- Fase 6.1: Máquina de estados explícita nos formulários (PENDENTE nunca é destino).
- Fase 6.2: Permissão exclusiva para 'Não Aplicável' (Gestor SecOps) e justificativa obrigatória.
"""

from django import forms
from django.core.exceptions import ValidationError

from .models import ItemChecklistOffboarding, Sistema


class RevogacaoItemForm(forms.Form):
    status = forms.ChoiceField(
        choices=[],
        required=False,
        widget=forms.Select(
            attrs={
                "class": "w-full px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-white focus:outline-none focus:ring-1 focus:ring-sky-500"
            }
        ),
    )
    evidencia_revogacao = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Ex: Ticket GLPI #4582 / Conta desativada no AD",
                "class": "w-full px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-sky-500",
            }
        ),
    )
    observacao = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Observações técnicas complementares (ou justificativa para Não Aplicável)",
                "class": "w-full px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-sky-500",
            }
        ),
    )

    def __init__(self, *args, item=None, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.item = item
        self.user = user

        status_atual = item.status if item else ItemChecklistOffboarding.StatusItem.PENDENTE

        # Fase 6.1: Define destinos válidos com base no status atual (PENDENTE nunca é destino)
        choices = []
        if status_atual == ItemChecklistOffboarding.StatusItem.PENDENTE:
            choices.append((ItemChecklistOffboarding.StatusItem.REVOGADO, "Revogado com Sucesso"))
            choices.append((ItemChecklistOffboarding.StatusItem.FALHA, "Falha / Bloqueado com Erro"))
            choices.append((ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL, "Não Aplicável"))
        elif status_atual == ItemChecklistOffboarding.StatusItem.FALHA:
            # Retry permitido após falha
            choices.append((ItemChecklistOffboarding.StatusItem.REVOGADO, "Revogado com Sucesso"))
            choices.append((ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL, "Não Aplicável"))
        else:
            choices.append(
                (status_atual, dict(ItemChecklistOffboarding.StatusItem.choices).get(status_atual, status_atual))
            )

        self.fields["status"].choices = choices
        if choices:
            self.fields["status"].initial = choices[0][0]

    def clean_status(self):
        status = self.cleaned_data.get("status")
        if not status:
            return ItemChecklistOffboarding.StatusItem.REVOGADO
        if status == ItemChecklistOffboarding.StatusItem.PENDENTE:
            raise ValidationError("O status 'Pendente' não pode ser selecionado como ação de revogação.")
        if status == ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL:
            if self.user and not self.user.has_perm("governance.marcar_nao_aplicavel"):
                raise ValidationError(
                    "Apenas o Gestor SecOps possui autorização para marcar um acesso como Não Aplicável."
                )
        return status

    def clean_evidencia_revogacao(self):
        evidencia = self.cleaned_data.get("evidencia_revogacao", "").strip()

        if self.item:
            sistema = self.item.vinculo_acesso.sistema
            sensivel = (
                sistema.criticidade in [Sistema.Criticidade.CRITICA, Sistema.Criticidade.ALTA]
                or sistema.armazena_dados_lgpd
            )
            # Para sistemas críticos ou com dados pessoais (LGPD), a evidência é obrigatória para REVOGADO/FALHA
            status_solicitado = self.cleaned_data.get("status")
            if sensivel and not evidencia and status_solicitado != ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL:
                raise ValidationError(
                    f"A evidência de revogação (ID do chamado, ticket GLPI ou log) é estritamente obrigatória "
                    f"para o sistema '{sistema.nome}', classificado com Criticidade {sistema.get_criticidade_display()} ou escopo LGPD."
                )

        # Rejeitar texto vago / genérico
        if evidencia.lower() in ["revogado manualmente", "teste", "ok", "revogado"]:
            raise ValidationError(
                "Informe uma evidência válida (ex: número de ticket, código de chamado ou nota de auditoria)."
            )

        return evidencia

    def clean(self):
        cleaned_data = super().clean()
        status = cleaned_data.get("status")
        observacao = (cleaned_data.get("observacao") or "").strip()

        # Fase 6.2: Validação de autorização e justificativa de Não Aplicável
        if status == ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL:
            if self.user and not self.user.has_perm("governance.marcar_nao_aplicavel"):
                raise ValidationError(
                    "Apenas o Gestor SecOps possui autorização para marcar um acesso como Não Aplicável."
                )
            if len(observacao) < 20:
                self.add_error(
                    "observacao",
                    "A marcação de 'Não Aplicável' exige justificativa técnica detalhada no campo observação (mínimo de 20 caracteres).",
                )

        return cleaned_data
