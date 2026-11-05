"""
Camada de Serviços de Negócio (Domain Services) para Governança & IAM.

Fase 1.3: Transações atômicas, bloqueio de concorrência (select_for_update)
e garantia de idempotência no encerramento de acessos.
"""

import logging
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError
from .models import ItemChecklistOffboarding, VinculoAcesso, ProcessoOffboarding, Colaborador

logger = logging.getLogger('gatekeeper.audit')


@transaction.atomic
def revogar_item_checklist(item_id, responsavel, evidencia, observacao="", status=ItemChecklistOffboarding.StatusItem.REVOGADO):
    """
    Executa a revogação atômica de um item do checklist de offboarding com bloqueio pessimista de linha.
    Garante não-repúdio e idempotência (rejeita sobrescrever um item já resolvido).
    """
    # Bloqueio pessimista de linha para evitar condições de corrida (double submit)
    item = ItemChecklistOffboarding.objects.select_for_update().select_related(
        'processo', 'vinculo_acesso__sistema', 'processo__colaborador'
    ).get(pk=item_id)

    # Idempotência: impede re-revogação sobrescrevendo histórico prévio
    if item.status != ItemChecklistOffboarding.StatusItem.PENDENTE:
        raise ValidationError(f"Este acesso já foi finalizado anteriormente com status: {item.get_status_display()}.")

    agora = timezone.now()

    # 1. Atualizar o Item do Checklist
    item.status = status
    item.revogado = (status == ItemChecklistOffboarding.StatusItem.REVOGADO)
    item.data_revogacao = agora
    item.responsavel_revogacao = responsavel
    item.evidencia_revogacao = evidencia
    item.observacao = observacao
    item.save()

    # 2. Atualizar o Vínculo de Acesso correspondente
    vinculo = item.vinculo_acesso
    if status == ItemChecklistOffboarding.StatusItem.REVOGADO:
        vinculo.status = VinculoAcesso.StatusAcesso.REVOGADO
        vinculo.data_revogacao = agora
        vinculo.revogado_por = responsavel
        vinculo.justificativa = f"Offboarding executado. Evidência: {evidencia}"
        vinculo.save()

    logger.info(
        f"OFFBOARDING_ITEM_REVOKED: colaborador='{item.processo.colaborador.nome_completo}' "
        f"sistema='{vinculo.sistema.nome}' conta='{vinculo.identificador_conta}' "
        f"status='{status}' operador='{responsavel.username}' evidencia='{evidencia}'"
    )

    # 3. Avaliar conclusão global do Processo de Offboarding
    processo = item.processo
    total_itens = processo.itens_checklist.count()
    itens_resolvidos = processo.itens_checklist.exclude(status=ItemChecklistOffboarding.StatusItem.PENDENTE).count()

    if total_itens > 0 and itens_resolvidos == total_itens:
        # Se houver itens com falha, o processo fica retido em PENDENTE com alerta
        possui_falha = processo.itens_checklist.filter(status=ItemChecklistOffboarding.StatusItem.FALHA).exists()
        if possui_falha:
            processo.status = ProcessoOffboarding.StatusOffboarding.PENDENTE
        else:
            processo.status = ProcessoOffboarding.StatusOffboarding.CONCLUIDO
            processo.concluido_em = agora

        processo.save()

        # Colaborador marcado como DESLIGADO com data local (America/Bahia)
        colab = processo.colaborador
        colab.status = Colaborador.StatusColaborador.DESLIGADO
        if not colab.data_desligamento:
            colab.data_desligamento = timezone.localdate()
        colab.save()

        logger.info(f"OFFBOARDING_PROCESS_CONCLUDED: colaborador='{colab.nome_completo}' operador='{responsavel.username}'")

    return item, processo

