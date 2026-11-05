"""
Camada de Serviços de Negócio (Domain Services) para Governança & IAM.

Contempla:
- Fase 1.3: Transações atômicas, bloqueio de concorrência (select_for_update) e idempotência.
- Fase 6.1: Máquina de estados explícita com suporte a retry em FALHA (FALHA -> REVOGADO).
- Fase 6.2: Não Aplicável auditável (justificativa obrigatória e encerramento de vínculo ativo).
- Fase 6.3: Concorrência e bloqueio hierárquico ordenado (processo -> item) para prevenir deadlocks.
"""

import logging

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from .models import Colaborador, ItemChecklistOffboarding, ProcessoOffboarding, VinculoAcesso

logger = logging.getLogger("gatekeeper.audit")

S = ItemChecklistOffboarding.StatusItem

# Fase 6.1: Máquina de estados estrita (Deny by Default)
TRANSICOES_PERMITIDAS = {
    S.PENDENTE: {S.REVOGADO, S.FALHA, S.NAO_APLICAVEL},
    S.FALHA: {S.REVOGADO, S.NAO_APLICAVEL},  # Nova tentativa permitida após falha
    # REVOGADO e NAO_APLICAVEL são estados finais imutáveis
}


def validar_transicao_item(status_atual, novo_status):
    """
    Valida se a transição entre estados de um item do checklist é permitida pelas regras de negócio.
    """
    if status_atual in {S.REVOGADO, S.NAO_APLICAVEL}:
        raise ValidationError(
            f"Transição de status não permitida: este acesso já foi finalizado anteriormente com status: {status_atual}."
        )
    destinos_validos = TRANSICOES_PERMITIDAS.get(status_atual, set())
    if novo_status not in destinos_validos:
        raise ValidationError(
            f"Transição de status não permitida: '{status_atual}' não pode transitar para '{novo_status}'."
        )


@transaction.atomic
def iniciar_offboarding(colaborador_id, responsavel, motivo="Desligamento Formal"):
    """
    Inicia o fluxo formal de offboarding com bloqueio pessimista no colaborador.
    Garante atomicidade e prevenção contra processos concorrentes duplicados (Fase 6.3).
    Marca imediatamente o colaborador como DESLIGADO.
    """
    colaborador = Colaborador.objects.select_for_update().get(pk=colaborador_id)

    # Previne duplicidade de processos abertos simultaneamente
    processo_ativo = colaborador.processos_offboarding.filter(
        status__in=[ProcessoOffboarding.StatusOffboarding.INICIADO, ProcessoOffboarding.StatusOffboarding.PENDENTE]
    ).first()
    if processo_ativo:
        return processo_ativo, False

    agora = timezone.now()
    hoje = timezone.localdate()

    # Marca imediatamente como DESLIGADO para mitigar concessões indevidas
    colaborador.status = Colaborador.StatusColaborador.DESLIGADO
    if not colaborador.data_desligamento:
        colaborador.data_desligamento = hoje
    colaborador.save()

    processo = ProcessoOffboarding.objects.create(
        colaborador=colaborador,
        responsavel_ti=responsavel,
        status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        observacoes=motivo,
    )

    # Cria itens do checklist para todos os vínculos que não estejam REVOGADO (ATIVO, BLOQUEADO)
    acessos_a_revogar = colaborador.vinculos_acesso.exclude(status=VinculoAcesso.StatusAcesso.REVOGADO)
    itens = [
        ItemChecklistOffboarding(
            processo=processo,
            vinculo_acesso=v,
            status=ItemChecklistOffboarding.StatusItem.PENDENTE,
        )
        for v in acessos_a_revogar
    ]
    if itens:
        ItemChecklistOffboarding.objects.bulk_create(itens)

    # Se o colaborador não possuía nenhum acesso pendente, conclui de imediato
    if not acessos_a_revogar.exists():
        processo.status = ProcessoOffboarding.StatusOffboarding.CONCLUIDO
        processo.concluido_em = agora
        processo.save()
        logger.info(
            "OFFBOARDING_PROCESS_INITIATED",
            extra={
                "audit": {
                    "colaborador": colaborador.nome_completo,
                    "colaborador_id": colaborador.pk,
                    "operador": responsavel.username,
                    "motivo": (motivo or "")[:500],
                    "total_itens": 0,
                    "status_processo": processo.status,
                }
            },
        )
    else:
        logger.info(
            "OFFBOARDING_PROCESS_INITIATED",
            extra={
                "audit": {
                    "colaborador": colaborador.nome_completo,
                    "colaborador_id": colaborador.pk,
                    "operador": responsavel.username,
                    "motivo": (motivo or "")[:500],
                    "total_itens": len(itens),
                    "status_processo": processo.status,
                }
            },
        )

    return processo, True


@transaction.atomic
def revogar_item_checklist(
    item_id, responsavel, evidencia, observacao="", status=ItemChecklistOffboarding.StatusItem.REVOGADO
):
    """
    Executa a revogação de um item com bloqueio pessimista ordenado (processo -> item).
    Valida a máquina de estados (Fase 6.1).
    Se NAO_APLICAVEL: exige justificativa (>= 20 caracteres) e encerra o vínculo (Fase 6.2).
    Recalcula a conclusão do processo com suporte a retry após falhas.
    """
    # 1. Bloqueio hierárquico ordenado (Pai -> Filho) para evitar deadlocks e concorrência (Fase 6.3)
    item_meta = ItemChecklistOffboarding.objects.values("processo_id").get(pk=item_id)
    processo = ProcessoOffboarding.objects.select_for_update().get(pk=item_meta["processo_id"])
    item = (
        ItemChecklistOffboarding.objects.select_for_update()
        .select_related("processo", "vinculo_acesso__sistema", "processo__colaborador")
        .get(pk=item_id)
    )

    # 2. Validação da máquina de estados (Fase 6.1)
    validar_transicao_item(item.status, status)

    agora = timezone.now()

    # 3. Regra de Negócio: Não Aplicável exige justificativa detalhada (Fase 6.2)
    if status == ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL:
        justificativa = (observacao or "").strip()
        if len(justificativa) < 20:
            raise ValidationError(
                "A marcação de 'Não Aplicável' exige justificativa técnica detalhada no campo observação (mínimo de 20 caracteres)."
            )

    # 4. Atualizar o Item do Checklist
    item.status = status
    item.revogado = status == ItemChecklistOffboarding.StatusItem.REVOGADO
    item.data_revogacao = agora
    item.responsavel_revogacao = responsavel
    item.evidencia_revogacao = evidencia
    item.observacao = observacao
    item.save()

    # 5. Atualizar o Vínculo de Acesso correspondente (Fase 6.2 - Não Aplicável encerra vínculo ativo)
    vinculo = item.vinculo_acesso
    if status == ItemChecklistOffboarding.StatusItem.REVOGADO:
        vinculo.status = VinculoAcesso.StatusAcesso.REVOGADO
        vinculo.data_revogacao = agora
        vinculo.revogado_por = responsavel
        vinculo.justificativa = f"Offboarding executado. Evidência: {evidencia}"
        vinculo.save()
    elif status == ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL:
        vinculo.status = VinculoAcesso.StatusAcesso.REVOGADO
        vinculo.data_revogacao = agora
        vinculo.revogado_por = responsavel
        vinculo.justificativa = f"Não aplicável: {observacao}"
        vinculo.save()

    logger.info(
        "OFFBOARDING_ITEM_REVOKED",
        extra={
            "audit": {
                "colaborador": item.processo.colaborador.nome_completo,
                "colaborador_id": item.processo.colaborador.pk,
                "sistema": vinculo.sistema.nome,
                "conta": vinculo.identificador_conta,
                "status": status,
                "operador": responsavel.username,
                "evidencia": (evidencia or "")[:500],
                "observacao": (observacao or "")[:500],
            }
        },
    )

    # 6. Recalcular o status global do Processo de Offboarding
    itens_totais = processo.itens_checklist.count()
    itens_resolvidos = processo.itens_checklist.exclude(status=ItemChecklistOffboarding.StatusItem.PENDENTE).count()
    possui_falha = processo.itens_checklist.filter(status=ItemChecklistOffboarding.StatusItem.FALHA).exists()

    if itens_totais > 0 and itens_resolvidos == itens_totais:
        if possui_falha:
            processo.status = ProcessoOffboarding.StatusOffboarding.PENDENTE
            processo.concluido_em = None
        else:
            processo.status = ProcessoOffboarding.StatusOffboarding.CONCLUIDO
            processo.concluido_em = agora
    else:
        if possui_falha:
            processo.status = ProcessoOffboarding.StatusOffboarding.PENDENTE
        else:
            processo.status = ProcessoOffboarding.StatusOffboarding.INICIADO
        processo.concluido_em = None

    processo.save()

    # Garante colaborador como DESLIGADO
    colab = processo.colaborador
    if colab.status != Colaborador.StatusColaborador.DESLIGADO:
        colab.status = Colaborador.StatusColaborador.DESLIGADO
        if not colab.data_desligamento:
            colab.data_desligamento = timezone.localdate()
        colab.save()

    if processo.status == ProcessoOffboarding.StatusOffboarding.CONCLUIDO:
        logger.info(
            "OFFBOARDING_PROCESS_CONCLUDED",
            extra={
                "audit": {
                    "colaborador": colab.nome_completo,
                    "colaborador_id": colab.pk,
                    "operador": responsavel.username,
                    "processo_id": processo.pk,
                }
            },
        )

    return item, processo
