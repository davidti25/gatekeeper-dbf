"""
Camada de Serviços de Negócio (Domain Services) para Governança & IAM.

Contempla:
- Fase 1.3: Transações atômicas, bloqueio de concorrência (select_for_update) e idempotência.
- Fase 6.1: Máquina de estados explícita com suporte a retry em FALHA (FALHA -> REVOGADO).
- Fase 6.2: Não Aplicável auditável (justificativa obrigatória e encerramento de vínculo ativo).
- Fase 6.3: Concorrência e bloqueio hierárquico ordenado (processo -> item) para prevenir deadlocks.
"""

import logging

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from .models import (
    CampanhaRevisao,
    Colaborador,
    ItemChecklistOffboarding,
    ItemRevisao,
    ProcessoOffboarding,
    Sistema,
    VinculoAcesso,
)

logger = logging.getLogger("gatekeeper.audit")

S = ItemChecklistOffboarding.StatusItem

CRITICIDADE_NIVEL = {
    Sistema.Criticidade.BAIXA: 1,
    Sistema.Criticidade.MEDIA: 2,
    Sistema.Criticidade.ALTA: 3,
    Sistema.Criticidade.CRITICA: 4,
}

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
    if colaborador.usuario_id and colaborador.usuario.is_active:
        colaborador.usuario.is_active = False
        colaborador.usuario.save(update_fields=["is_active"])
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

    # 3. Regra de Negócio: Não Aplicável exige permissão e justificativa detalhada (Fase 6.2 e 12.1)
    if status == ItemChecklistOffboarding.StatusItem.NAO_APLICAVEL:
        if not responsavel.has_perm("governance.marcar_nao_aplicavel"):
            raise PermissionDenied(
                "Apenas o Gestor SecOps possui autorização para marcar um acesso como Não Aplicável."
            )
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


User = None


def _get_user_model_lazy():
    global User
    if User is None:
        from django.contrib.auth import get_user_model

        User = get_user_model()
    return User


def determinar_revisor(vinculo):
    """
    Fase 15.2: Determina o revisor para um vínculo seguindo a ordem de precedência:
    1. Gestor imediato do colaborador (se possuir usuário ativo e != colaborador.usuario)
    2. Dono do sistema (se possuir usuário ativo e != colaborador.usuario)
    3. Fila do grupo Gestor SecOps (usuário ativo != colaborador.usuario)
    Retorna o User revisor ou None se não encontrar nenhum elegível.
    """
    user_cls = _get_user_model_lazy()
    colab_user = getattr(vinculo.colaborador, "usuario", None)

    # 1. Gestor imediato
    gestor = vinculo.colaborador.gestor_imediato
    if gestor and gestor.usuario and gestor.usuario.is_active:
        if not colab_user or gestor.usuario_id != colab_user.id:
            return gestor.usuario

    # 2. Dono do sistema
    dono = vinculo.sistema.dono
    if dono and dono.is_active:
        if not colab_user or dono.id != colab_user.id:
            return dono

    # 3. Fila do grupo Gestor SecOps
    gestores_secops = user_cls.objects.filter(groups__name="Gestor SecOps", is_active=True).order_by("id")
    for g in gestores_secops:
        if not colab_user or g.id != colab_user.id:
            return g

    return None


@transaction.atomic
def abrir_campanha(
    nome,
    prazo,
    criada_por,
    descricao="",
    escopo_criticidade_minima=None,
    escopo_departamentos=None,
):
    """
    Fase 15.2: Tira uma fotografia auditável: cria um ItemRevisao para cada VinculoAcesso ATIVO no escopo.
    """
    if prazo < timezone.localdate():
        raise ValidationError("O prazo da campanha não pode ser uma data retroativa.")

    campanha = CampanhaRevisao.objects.create(
        nome=nome,
        descricao=descricao,
        escopo_criticidade_minima=escopo_criticidade_minima or None,
        prazo=prazo,
        criada_por=criada_por,
        status=CampanhaRevisao.StatusCampanha.ABERTA,
    )
    if escopo_departamentos:
        campanha.escopo_departamentos.set(escopo_departamentos)

    # Fotografia: apenas vínculos ATIVOS no momento da abertura
    vinculos = VinculoAcesso.objects.filter(status=VinculoAcesso.StatusAcesso.ATIVO).select_related(
        "colaborador__gestor_imediato__usuario",
        "colaborador__usuario",
        "sistema__dono",
    )

    if escopo_departamentos:
        vinculos = vinculos.filter(colaborador__departamento__in=escopo_departamentos)

    if escopo_criticidade_minima:
        nivel_minimo = CRITICIDADE_NIVEL.get(escopo_criticidade_minima, 1)
        sistemas_validos = [
            s.id for s in Sistema.objects.all() if CRITICIDADE_NIVEL.get(s.criticidade, 1) >= nivel_minimo
        ]
        vinculos = vinculos.filter(sistema_id__in=sistemas_validos)

    itens_para_criar = []
    itens_sem_revisor = 0

    for v in vinculos:
        revisor = determinar_revisor(v)
        colab_user = getattr(v.colaborador, "usuario", None)

        if not revisor:
            itens_sem_revisor += 1
            logger.warning(
                "REVIEW_UNASSIGNED_ITEM",
                extra={
                    "audit": {
                        "vinculo_id": v.id,
                        "colaborador": v.colaborador.nome_completo,
                        "sistema": v.sistema.nome,
                        "motivo": "Nenhum revisor elegível encontrado respeitando segregação de funções",
                    }
                },
            )
            # Fallback de segurança: atribui ao criador da campanha se este não for o próprio colaborador
            if criada_por and (not colab_user or criada_por.id != colab_user.id):
                revisor = criada_por

        if revisor:
            itens_para_criar.append(
                ItemRevisao(
                    campanha=campanha,
                    vinculo=v,
                    revisor=revisor,
                    decisao=ItemRevisao.DecisaoRevisao.PENDENTE,
                )
            )

    if itens_para_criar:
        ItemRevisao.objects.bulk_create(itens_para_criar)

    logger.info(
        "REVIEW_CAMPAIGN_OPENED",
        extra={
            "audit": {
                "campanha_id": campanha.id,
                "nome": campanha.nome,
                "prazo": str(campanha.prazo),
                "criada_por": criada_por.username,
                "total_itens": len(itens_para_criar),
                "itens_sem_revisor_alerta": itens_sem_revisor,
            }
        },
    )

    return campanha


@transaction.atomic
def registrar_decisao(item_id, decisao, justificativa, usuario):
    """
    Fase 15.2: Registra a decisão de um item de revisão com select_for_update,
    validando segregação de funções, prazos e integridade das justificativas.
    """
    item = (
        ItemRevisao.objects.select_for_update()
        .select_related("campanha", "vinculo__colaborador__usuario", "vinculo__sistema")
        .get(pk=item_id)
    )

    # 1. Campanha deve estar aberta
    if item.campanha.status != CampanhaRevisao.StatusCampanha.ABERTA:
        raise ValidationError("Não é permitido registrar decisões em campanhas já encerradas.")

    # 2. Revisor designado
    if item.revisor_id != usuario.id:
        raise PermissionDenied("Apenas o revisor designado pode decidir sobre este item.")

    # 3. Segregação de funções revalidada no momento da decisão
    colab_user = getattr(item.vinculo.colaborador, "usuario", None)
    if colab_user and usuario.id == colab_user.id:
        raise PermissionDenied("Segregação de funções: o usuário não pode revisar o próprio acesso.")

    # 4. Máquina de estados
    if item.decisao != ItemRevisao.DecisaoRevisao.PENDENTE:
        raise ValidationError(f"Este item já foi decidido anteriormente como {item.get_decisao_display()}.")

    if decisao not in {ItemRevisao.DecisaoRevisao.MANTER, ItemRevisao.DecisaoRevisao.REVOGAR}:
        raise ValidationError(f"Decisão inválida: '{decisao}'. Opções válidas: MANTER ou REVOGAR.")

    # 5. Justificativa
    justificativa = (justificativa or "").strip()
    if decisao == ItemRevisao.DecisaoRevisao.REVOGAR:
        if len(justificativa) < 20:
            raise ValidationError("Justificativa obrigatória (mínimo de 20 caracteres) para decisões de REVOGAR.")

    if decisao == ItemRevisao.DecisaoRevisao.MANTER:
        if item.vinculo.sistema.criticidade == Sistema.Criticidade.CRITICA:
            if len(justificativa) < 20:
                raise ValidationError(
                    "Justificativa obrigatória (mínimo de 20 caracteres) para MANTER acesso em sistema de criticidade CRÍTICA."
                )

    item.decisao = decisao
    item.justificativa = justificativa
    item.decidido_em = timezone.now()
    item.decidido_por = usuario
    item.save()

    logger.info(
        "REVIEW_DECISION",
        extra={
            "audit": {
                "campanha": item.campanha.nome,
                "campanha_id": item.campanha.id,
                "item_id": item.id,
                "colaborador": item.vinculo.colaborador.nome_completo,
                "colaborador_id": item.vinculo.colaborador.id,
                "sistema": item.vinculo.sistema.nome,
                "identificador_conta": item.vinculo.identificador_conta,
                "revisor": usuario.username,
                "decisao": decisao,
                "justificativa": justificativa,
            }
        },
    )

    return item


@transaction.atomic
def registrar_decisao_lote(itens_ids, decisao, justificativa, usuario):
    """
    Fase 15.5: Decisão em lote estritamente para itens de criticidade BAIXA ou MEDIA.
    Se algum item for ALTA ou CRITICA, rejeita a operação em lote inteira.
    """
    itens = list(
        ItemRevisao.objects.filter(
            id__in=itens_ids,
            revisor=usuario,
            campanha__status=CampanhaRevisao.StatusCampanha.ABERTA,
        ).select_related("vinculo__sistema")
    )

    if not itens:
        raise ValidationError("Nenhum item válido encontrado para decisão em lote.")

    itens_criticos = [
        item.id
        for item in itens
        if item.vinculo.sistema.criticidade in {Sistema.Criticidade.ALTA, Sistema.Criticidade.CRITICA}
    ]
    if itens_criticos:
        raise ValidationError(
            "Decisão em lote não permitida para acessos de criticidade ALTA ou CRÍTICA. "
            "Esses itens devem ser revisados e decididos individualmente."
        )

    resultados = []
    for item in itens:
        res = registrar_decisao(item.id, decisao, justificativa, usuario)
        resultados.append(res)
    return resultados


@transaction.atomic
def executar_revogacao_revisao(item_id, evidencia, usuario):
    """
    Fase 15.3: Execução técnica pela TI da revogação decorrente de uma decisão REVOGAR.
    Atualiza o VinculoAcesso para REVOGADO somente após comprovação por evidência.
    """
    item = ItemRevisao.objects.select_for_update().select_related("vinculo", "campanha").get(pk=item_id)

    if item.decisao != ItemRevisao.DecisaoRevisao.REVOGAR:
        raise ValidationError("Apenas itens com decisão 'REVOGAR' podem ser executados para revogação.")

    if item.tarefa_revogada:
        raise ValidationError("A revogação deste acesso já foi executada e comprovada anteriormente.")

    evidencia = (evidencia or "").strip()
    if not evidencia:
        raise ValidationError("Evidência técnica da revogação é obrigatória.")

    agora = timezone.now()
    item.tarefa_revogada = True
    item.evidencia_revogacao = evidencia
    item.executado_em = agora
    item.executado_por = usuario
    item.save()

    # Atualiza o vínculo real para REVOGADO
    vinculo = item.vinculo
    vinculo.status = VinculoAcesso.StatusAcesso.REVOGADO
    vinculo.data_revogacao = agora
    vinculo.revogado_por = usuario
    vinculo.save()

    logger.info(
        "REVIEW_REVOCATION_EXECUTED",
        extra={
            "audit": {
                "campanha_id": item.campanha_id,
                "item_id": item.id,
                "vinculo_id": vinculo.id,
                "colaborador": vinculo.colaborador.nome_completo,
                "sistema": vinculo.sistema.nome,
                "identificador_conta": vinculo.identificador_conta,
                "operador_ti": usuario.username,
                "evidencia": evidencia,
            }
        },
    )

    return item


@transaction.atomic
def encerrar_campanha(campanha_id, usuario, forcar=False):
    """
    Fase 15.2: Encerra uma campanha de revisão.
    Permitido se todos os itens foram decididos OU se a campanha já ultrapassou o prazo limite (ou forçar=True).
    """
    campanha = CampanhaRevisao.objects.select_for_update().get(pk=campanha_id)

    if campanha.status == CampanhaRevisao.StatusCampanha.ENCERRADA:
        raise ValidationError("Esta campanha já foi encerrada anteriormente e não pode ser reaberta.")

    hoje = timezone.localdate()
    itens_pendentes = campanha.itens.filter(decisao=ItemRevisao.DecisaoRevisao.PENDENTE).count()

    if itens_pendentes > 0 and hoje <= campanha.prazo and not forcar:
        raise ValidationError(
            f"A campanha possui {itens_pendentes} item(ns) pendente(s) e o prazo ({campanha.prazo.strftime('%d/%m/%Y')}) ainda não expirou."
        )

    campanha.status = CampanhaRevisao.StatusCampanha.ENCERRADA
    campanha.encerrada_em = timezone.now()
    campanha.save()

    logger.info(
        "REVIEW_CAMPAIGN_CLOSED",
        extra={
            "audit": {
                "campanha_id": campanha.id,
                "nome": campanha.nome,
                "encerrada_por": usuario.username,
                "total_itens": campanha.total_itens,
                "itens_pendentes_nao_revisados": itens_pendentes,
            }
        },
    )

    return campanha
