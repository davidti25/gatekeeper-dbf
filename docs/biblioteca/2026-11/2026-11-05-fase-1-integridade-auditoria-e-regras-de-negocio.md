# 🛡️ Diário de Bordo: 2026-11-05 - Fase 1: Integridade da Auditoria & Regras de Negócio

* **Data:** 05 de Novembro de 2026
* **Projeto:** GateKeeper-DBF (Central de Governança de Acessos & Offboarding Seguro)
* **Autor / Responsável:** David B. F.
* **Origem:** Implementação da Fase 1 do Plano de Ação de Segurança & Qualidade
* **Fase:** Fase 1 — Integridade da Auditoria & Regras de Negócio (CIS Controls v8 5.5 / LGPD Art. 46)
* **Status:** ✅ Concluída

---

## 1. 🎯 Objetivos Executados & Implementações Técnicas

### 1.1 Proteção contra Expurgo Acidental de Evidências (`on_delete=models.PROTECT`)
* **Problema:** A deleção acidental de um colaborador apagava em cascata (`CASCADE`) seus vínculos de acesso concedidos, o processo de offboarding e o checklist de encerramento, destruindo a trilha de auditoria e conformidade exigida pelo CIS 5.5 e LGPD Art. 46.
* **Solução Implementada:**
  * Substituído `CASCADE` por `models.PROTECT` em:
    * `VinculoAcesso.colaborador`
    * `ProcessoOffboarding.colaborador`
    * `ItemChecklistOffboarding.vinculo_acesso`
  * Adicionado bloqueio no Django Admin (`has_delete_permission(request, obj=None): return False`) para `ColaboradorAdmin`, `VinculoAcessoAdmin`, `ProcessoOffboardingAdmin` e `ItemChecklistOffboardingAdmin`.
  * Colaboradores que deixam a organização recebem status `DESLIGADO`, mantendo seus registros históricos e rastreáveis perpetuamente.

### 1.2 Rastreabilidade Temporal & Trilha de Auditoria (`django-simple-history`)
* **Solução Implementada:**
  * Instalada a biblioteca `django-simple-history` (v3.13.0) e atualizado o `requirements.txt`.
  * Registrado `'simple_history'` em `INSTALLED_APPS` e `'simple_history.middleware.HistoryRequestMiddleware'` em `MIDDLEWARE` no [`core/settings.py`](../../../core/settings.py).
  * Adicionado `HistoricalRecords()` nos modelos críticos:
    * `Colaborador`
    * `Sistema`
    * `VinculoAcesso`
    * `ProcessoOffboarding`
    * `ItemChecklistOffboarding`
  * Integrado `SimpleHistoryAdmin` nos administradores de modelo em [`apps/governance/admin.py`](../../../apps/governance/admin.py), permitindo inspecionar cada versão, quem alterou e quando.

### 1.3 Camada de Serviços, Atomicidade e Idempotência (`services.py`)
* **Problema:** A revogação manual de acessos via views alterava registros múltiplos sem bloco de transação segura. Dois cliques simultâneos podiam sobrescrever evidências, datas ou duplicar confirmações de revogação.
* **Solução Implementada:**
  * Criado o módulo [`apps/governance/services.py`](../../../apps/governance/services.py) contendo a função transacional `revogar_item_checklist()`:
    * Anotação `@transaction.atomic` garantindo que o item do checklist, vínculo de acesso, processo de offboarding e colaborador sejam atualizados atomicamente (tudo ou nada).
    * Bloqueio pessimista de linha via `select_for_update()` para eliminar condições de corrida (*race conditions* / *double submit*).
    * Garantia de **idempotência**: se o item já foi finalizado (`status != PENDENTE`), a requisição é recusada com `ValidationError`.

### 1.4 Validação Estrita de Evidências em Ativos Críticos e Escopo LGPD (`forms.py`)
* **Problema:** O aceite de evidências em branco ou preenchidas com textos vagos ("Revogado manualmente", "teste", "ok") invalidava a comprovação forense e técnica perante auditorias de SOC e órgãos reguladores (ANPD).
* **Solução Implementada:**
  * Criado o formulário [`apps/governance/forms.py`](../../../apps/governance/forms.py) (`RevogacaoItemForm`):
    * Exige obrigatoriamente evidência (ID de chamado GLPI/ITSM, log de auditoria ou ticket) quando o sistema vinculado possuir criticidade `CRITICA`, `ALTA` ou a flag `armazena_dados_lgpd=True`.
    * Rejeita ativamente termos vagos e genéricos (`"revogado manualmente"`, `"teste"`, `"ok"`, `"revogado"`).
    * Oferece seletor de status (`REVOGADO`, `FALHA`, `NAO_APLICAVEL`) com padrão seguro `REVOGADO`.

### 1.5 Correções Estruturais do Fluxo de Offboarding
* **Inclusão Abrangente de Acessos:** A geração de checklist no início do offboarding agora inclui todos os vínculos não revogados (`exclude(status=REVOGADO)`), cobrindo adequadamente contas em estado `BLOQUEADO`.
* **Desligamento Imediato no Início do Processo:** Ao disparar o offboarding, o colaborador é imediatamente sinalizado com `status = DESLIGADO` e `data_desligamento = timezone.localdate()` (fuso `America/Bahia`). O painel do SOC reflete o risco de contas órfãs imediatamente enquanto o checklist não for 100% resolvido.
* **Bloqueio de Concessão de Novos Acessos:** No método `clean()` de [`VinculoAcesso`](../../../apps/governance/models.py), novas concessões são proibidas caso o colaborador esteja desligado ou possua processo de offboarding ativo.
* **Suporte Formal a Recontratações:** Campo `ProcessoOffboarding.colaborador` flexibilizado para `ForeignKey` com `UniqueConstraint(fields=['colaborador'], condition=~Q(status='CONCLUIDO'))`, viabilizando múltiplos ciclos históricos sem colisão no banco.
* **Granularidade de Status no Checklist:** Introduzido `StatusItem` (`PENDENTE`, `REVOGADO`, `FALHA`, `NAO_APLICAVEL`). Caso haja pendências com falha, o processo fica retido em `PENDENTE` sinalizando intervenção técnica necessária.
* **Consistência de Fuso Horário:** Uso estrito de `timezone.localdate()` respeitando o fuso horário configurado `America/Bahia`.

---

## 2. 🧪 Validação Automatizada de Segurança & Regras de Negócio

Adicionada a classe de testes `Phase1AuditAndIntegrityTests` em [`apps/governance/tests.py`](../../../apps/governance/tests.py), elevando a suíte para **12 testes automatizados**:

1. `test_01_autenticacao_obrigatoria_redireciona_anonimos`: Redirecionamento 302 para login em todas as rotas.
2. `test_02_tela_de_login_disponivel_sem_autenticacao`: Exibição de formulário e CSRF token na tela pública de login.
3. `test_03_segregacao_funcoes_auditor_apenas_leitura`: Bloqueio 403 Forbidden para ações restritas tentadas por auditores.
4. `test_04_analista_ti_executa_offboarding_com_nao_repudio_estrito`: Execução de offboarding e checklist com registro de `request.user`.
5. `test_05_neutralizacao_stored_xss_data_confirm`: Mitigação de injeção XSS em campos de dados via script externo.
6. `test_06_master_root_acesso_total`: Validação de privilégios irrestritos da conta master `root` em ambiente de desenvolvimento.
7. `test_10_protecao_exclusao_acidental_on_delete_protect`: Bloqueio de deleção de colaborador/vínculo via `ProtectedError`.
8. `test_11_bloqueio_concessao_acesso_colaborador_desligado_ou_em_offboarding`: Rejeição com `ValidationError` de novos privilégios a colaboradores inativos ou em offboarding.
9. `test_12_servico_revogacao_atomica_e_idempotencia`: Validação de atomicidade e rejeição por idempotência de double submit no checklist.
10. `test_13_validacao_formulario_evidencia_obrigatoria_sistemas_criticos_e_lgpd`: Exigência de evidência estruturada em sistemas de alta criticidade e escopo LGPD.
11. `test_14_rastreabilidade_historica_simple_history`: Rastreamento de histórico temporal com `HistoricalRecords()`.
12. `test_15_suporte_recontratacao_colaborador`: Criação de novo processo de offboarding para colaborador recontratado sem colisão de constraints.

**Resultado da execução dos testes:**
```text
Found 12 test(s).
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
............
----------------------------------------------------------------------
Ran 12 tests in 15.947s

OK
Destroying test database for alias 'default'...
```

---

## 3. 🛡️ Mapeamento de Conformidade e Frameworks

* **CIS Controls v8 — Controle 5.5 (Centralized Account Deprovisioning):**
  * Checklist auditável com prazos, responsáveis de SOC e evidências obrigatórias para desativação de contas.
* **LGPD — Art. 46 (Segurança e Sigilo de Dados Pessoais):**
  * Bloqueio rigoroso de acessos a sistemas contendo dados pessoais (`armazena_dados_lgpd=True`) e preservação perene de evidências sem risco de deleção em cascata.
* **MITRE ATT&CK — T1078 (Valid Accounts):**
  * Eliminação de contas órfãs por identificação imediata de colaboradores com status `DESLIGADO` e processos ativos.
* **NIST SP 800-61 Rev. 2 (Incident Handling):**
  * Não-repúdio estrito e registro forense atômico com concorrência travada no banco de dados.

---

## 4. 📋 Próximo Passo

Avançar para a **Fase 2 (Plataforma & Hardening de Configuração)** do Plano de Ação:
* **2.2:** `pip-tools` com geração de hashes em `requirements.txt` + Dependabot.
* **2.3:** Front-end local (Tailwind / Lucide desvinculados de CDN externa) + CSP rígida sem `unsafe-inline`.
* **2.4:** Configuração de produção segura (`python manage.py check --deploy`).
* **2.5:** Revisão de permissões de diretórios e links da documentação.
