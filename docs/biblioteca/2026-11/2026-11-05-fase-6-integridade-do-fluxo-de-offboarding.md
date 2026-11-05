# 🛡️ Diário de Bordo: 2026-11-05 - Plano v2: Fase 6: Integridade do Fluxo de Offboarding

* **Data:** 05 de Novembro de 2026
* **Projeto:** GateKeeper-DBF (Central de Governança de Acessos & Offboarding Seguro)
* **Autor / Responsável:** David B. F.
* **Origem:** Implementação da Fase 6 do Plano de Ação v2 (Brechas Pós-Implementação)
* **Fase:** Fase 6 — Integridade do Fluxo de Offboarding & Máquina de Estados
* **Status:** ✅ Concluída

---

## 1. 🔍 Resumo Executivo & Severidade

* **Classificação de Severidade Residual:** `[BAIXA / CONTROLADA]` (Eliminada a possibilidade de processos presos indefinidamente em falha, inconsistências em "Não Aplicável", condições de corrida na abertura/revogação e relatórios com dados contraditórios).
* **Mapeamento Normativo:**
  * **CIS Controls v8:**
    * Salvaguarda 5.5 (*Centralize Account Revocation*): Trilha estrita onde nenhum encerramento de acesso deixa vínculo ativo residual.
    * Salvaguarda 6.8 (*Segregation of Duties*): Apenas Gestores de SecOps possuem autoridade para abonar contas como "Não Aplicável".
  * **ISO/IEC 27001:2022:** A.9.2.6 (*Removal or Adjustment of Access Rights*).
  * **LGPD (Lei 13.709/2018):** Art. 46 (Segurança e idoneidade de evidências de encerramento de acesso a dados pessoais).

* **O que foi implementado:**
  1. **Máquina de Estados Explícita (Fase 6.1):** Mapeamento estrito em `TRANSICOES_PERMITIDAS` em [`services.py`](../../apps/governance/services.py). Itens com status `FALHA` agora aceitam novas tentativas (`FALHA → REVOGADO` ou `FALHA → NAO_APLICAVEL`). Estados finais (`REVOGADO`, `NAO_APLICAVEL`) são imutáveis contra sobrescrita e `PENDENTE` é permanentemente proibido como destino de transição.
  2. **Tratamento Rigoroso de "Não Aplicável" (Fase 6.2):** A opção exige justificativa técnica auditável com pelo menos 20 caracteres e encerra compulsoriamente o `VinculoAcesso` (`status=REVOGADO`), garantindo a invariante: *se o processo foi concluído, nenhum vínculo lógico correspondente permanece como ATIVO*. Nova permissão `governance.marcar_nao_aplicavel` delegada exclusivamente ao grupo *Gestor SecOps*.
  3. **Concorrência e Travas Hierárquicas (Fase 6.3):** Função `iniciar_offboarding()` encapsulada em transação atômica com bloqueio pessimista `select_for_update()` no colaborador. Na revogação, o lock pessimista é adquirido na ordem pai ➔ filho (`ProcessoOffboarding` ➔ `ItemChecklistOffboarding`), eliminando riscos de deadlocks e inconsistências de conclusão simultânea.
  4. **Relatório à Prova de Contradição (Fase 6.4):** A view [`OffboardingRelatorioView`](../../apps/governance/views.py) valida a invariante de ausência de acessos ativos. Se houver desvio, exibe alerta visual ostensivo e altera o status para *"INCONSISTENTE (ACESSO ATIVO DETECTADO)"*.

---

## 2. 🎯 Mapeamento MITRE ATT&CK

| Tática | Técnica | ID | Mitigação no GateKeeper-DBF |
| :--- | :--- | :--- | :--- |
| **Persistence / Defense Evasion** | Valid Accounts: Dormant Accounts | `T1078` | "Não Aplicável" encerra o vínculo ativo no diretório IAM, impedindo a permanência oculta de contas ativas após a conclusão do offboarding. |
| **Defense Evasion** | Impair Defenses: Disable or Modify Tools | `T1562` | Permissão exclusiva para o perfil *Gestor SecOps* abonar itens como `NAO_APLICAVEL`, evitando que analistas operacionais encerrem checklists com atalhos não auditados. |
| **Execution** | Shared Modules / Race Conditions | `T1129 / T1055` | Locks pessimistas ordenados via `select_for_update()` eliminando inconsistências concorrentes de banco de dados. |

---

## 3. 🛠️ Arquivos Criados e Modificados

* [`apps/governance/models.py`](../../apps/governance/models.py): Adicionada permissão `marcar_nao_aplicavel` no `ItemChecklistOffboarding.Meta`.
* [`apps/governance/migrations/0005_alter_itemchecklistoffboarding_options.py`](../../apps/governance/migrations/0005_alter_itemchecklistoffboarding_options.py): Migração criando e atribuindo a permissão ao *Gestor SecOps*.
* [`apps/governance/services.py`](../../apps/governance/services.py): `TRANSICOES_PERMITIDAS`, `validar_transicao_item()`, `iniciar_offboarding()` atômico e `revogar_item_checklist()` com lock hierárquico.
* [`apps/governance/forms.py`](../../apps/governance/forms.py): `RevogacaoItemForm` com validação de permissão para `NAO_APLICAVEL` e justificativa $\ge 20$ chars.
* [`apps/governance/views.py`](../../apps/governance/views.py): Integração dos novos fluxos de serviço e verificação de inconsistência no relatório.
* [`templates/governance/offboarding_detail.html`](../../templates/governance/offboarding_detail.html): Suporte visual a retry em itens com falha e controle por permissão da opção de não aplicável.
* [`templates/governance/offboarding_relatorio.html`](../../templates/governance/offboarding_relatorio.html): Banner de alerta e badge de inconsistência.
* [`apps/governance/tests.py`](../../apps/governance/tests.py): Suite `Phase6OffboardingIntegrityAndStateMachineTests` com 6 novos testes unitários e de integração.

---

## 4. 🧪 Validação dos Testes

* **Total de Testes Automatizados:** 35 testes (6 novos testes na Fase 6).
* **Resultado:** `OK` (100% aprovados em ~52s).
* **Cobertura de Código (Coverage):**
  * `apps/governance/models.py`: **95%**
  * `apps/governance/services.py`: **96%**
  * `apps/governance/views.py`: **88%**
  * `apps/governance/forms.py`: **87%**
  * **Média do módulo:** **92%** (meta: $\ge 85\%$).

