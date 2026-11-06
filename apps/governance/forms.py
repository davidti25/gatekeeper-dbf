"""
Formulários de Validação para Governança e Offboarding (GateKeeper-DBF).

Contempla:
- Fase 1.4: Validação estrita de evidências em ativos críticos e escopo LGPD.
- Fase 6.1: Máquina de estados explícita nos formulários (PENDENTE nunca é destino).
- Fase 6.2: Permissão exclusiva para 'Não Aplicável' (Gestor SecOps) e justificativa obrigatória.
"""

from allauth.mfa.totp.forms import ActivateTOTPForm as AllauthActivateTOTPForm
from allauth.mfa.totp.internal import auth as totp_auth
from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone

from .models import Departamento, ItemChecklistOffboarding, ItemRevisao, Sistema


class GateKeeperActivateTOTPForm(AllauthActivateTOTPForm):
    """
    Formulário de ativação TOTP com preservação de segredo na sessão.

    Problema Resolvido:
    No allauth padrão, ActivateTOTPForm usa `regenerate=not self.is_bound`. Em cada GET
    ou recarregamento (F5), um novo segredo e um novo QR Code eram gerados, invalidando
    imediatamente o segredo que o usuário havia acabado de escanear no smartphone.

    Com `regenerate=False`, o segredo permanece estável durante toda a sessão de ativação.
    Após a ativação com sucesso, o allauth purga o segredo da sessão via `clear_totp_secret()`.
    """

    def __init__(self, *args, **kwargs) -> None:
        self.user = kwargs.pop("user")
        super(forms.Form, self).__init__(*args, **kwargs)
        self.secret = totp_auth.get_totp_secret(regenerate=False)


class RevogacaoItemForm(forms.Form):
    status = forms.ChoiceField(
        choices=[],
        required=False,
        widget=forms.Select(attrs={"class": "gk-input-sm"}),
    )
    evidencia_revogacao = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Ex: Ticket GLPI #4582 / Conta desativada no AD",
                "class": "gk-input-sm",
            }
        ),
    )
    observacao = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Observações técnicas complementares (ou justificativa para Não Aplicável)",
                "class": "gk-input-sm",
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


class AbrirCampanhaForm(forms.Form):
    """Fase 15.2: Formulário para abertura de uma nova campanha de revisão de acessos."""

    nome = forms.CharField(
        max_length=150,
        label="Nome da Campanha",
        widget=forms.TextInput(attrs={"placeholder": "Ex: Revisão Periódica Q4 2026", "class": "gk-input"}),
    )
    prazo = forms.DateField(
        label="Prazo Limite",
        widget=forms.DateInput(attrs={"type": "date", "class": "gk-input"}),
    )
    descricao = forms.CharField(
        required=False,
        label="Descrição / Motivo",
        widget=forms.Textarea(attrs={"rows": 3, "class": "gk-input"}),
    )
    escopo_criticidade_minima = forms.ChoiceField(
        required=False,
        label="Criticidade Mínima",
        choices=[("", "Todas as criticidades")] + list(Sistema.Criticidade.choices),
        widget=forms.Select(attrs={"class": "gk-input"}),
    )
    escopo_departamentos = forms.ModelMultipleChoiceField(
        queryset=Departamento.objects.filter(ativo=True),
        required=False,
        label="Departamentos no Escopo (opcional)",
        widget=forms.CheckboxSelectMultiple(),
    )

    def clean_prazo(self):
        prazo = self.cleaned_data.get("prazo")
        if prazo and prazo < timezone.localdate():
            raise ValidationError("O prazo da campanha não pode ser uma data retroativa.")
        return prazo


class DecisaoItemForm(forms.Form):
    """Fase 15.2: Formulário individual para revisor decidir MANTER ou REVOGAR um acesso."""

    decisao = forms.ChoiceField(
        choices=[
            (ItemRevisao.DecisaoRevisao.MANTER, "Manter Acesso"),
            (ItemRevisao.DecisaoRevisao.REVOGAR, "Revogar Acesso"),
        ],
        widget=forms.Select(attrs={"class": "gk-input-sm"}),
    )
    justificativa = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                "rows": 2,
                "placeholder": "Justificativa obrigatória (mín. 20 caracteres) para REVOGAR e para MANTER em sistema CRÍTICO",
                "class": "gk-input-sm",
            }
        ),
    )


class DecisaoLoteForm(forms.Form):
    """Fase 15.5: Formulário para decisão em lote (apenas BAIXA/MEDIA)."""

    itens_ids = forms.CharField(widget=forms.HiddenInput())
    decisao = forms.ChoiceField(
        choices=[
            (ItemRevisao.DecisaoRevisao.MANTER, "Manter Acessos Selecionados"),
            (ItemRevisao.DecisaoRevisao.REVOGAR, "Revogar Acessos Selecionados"),
        ],
        widget=forms.Select(attrs={"class": "gk-input"}),
    )
    justificativa = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                "rows": 2,
                "placeholder": "Justificativa comum para os acessos em lote (mín. 20 caracteres se revogar)",
                "class": "gk-input",
            }
        ),
    )


class ExecucaoRevogacaoRevisaoForm(forms.Form):
    """Fase 15.3: Formulário para a TI registrar evidência de revogação decorrente de revisão."""

    evidencia_revogacao = forms.CharField(
        label="Evidência da Revogação (Ticket / Log)",
        widget=forms.TextInput(
            attrs={
                "placeholder": "Ex: Ticket ITSM #12345 - Acesso removido no IAM",
                "class": "gk-input",
            }
        ),
    )

    def clean_evidencia_revogacao(self):
        evidencia = self.cleaned_data.get("evidencia_revogacao", "").strip()
        if not evidencia:
            raise ValidationError("A evidência da revogação é obrigatória.")
        if evidencia.lower() in ["ok", "teste", "removido", "revogado"]:
            raise ValidationError("Informe uma evidência válida e auditável (ex: chamado ou ticket).")
        return evidencia
