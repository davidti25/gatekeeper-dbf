# 🛡️ Diário de Bordo: 2026-11-05 - Fase 0: Emergência — Autenticação Obrigatória, RBAC & Hardening

* **Data:** 05 de Novembro de 2026
* **Projeto:** GateKeeper-DBF (Central de Governança de Acessos & Offboarding Seguro)
* **Autor / Responsável:** David B. F.
* **Origem:** Implementação da Fase 0 do Plano de Ação de Segurança & Qualidade
* **Fase:** Fase 0 — Emergência (Bloqueio de Acesso Inseguro)
* **Status:** ✅ Concluída

---

## 1. 🎯 Objetivos Executados & Correções de Segurança

1. **Autenticação Obrigatória em Todo o Sistema (Item 0.1):**
   * Ativado o `LoginRequiredMiddleware` no [`core/settings.py`](../../../core/settings.py) após `AuthenticationMiddleware`.
   * **Princípio de Segurança (Secure by Default):** Todas as views passam a exigir login por padrão; rotas públicas exigem liberação explícita.
   * Criada a tela de autenticação corporativa [`templates/registration/login.html`](../../../templates/registration/login.html) e configuradas as rotas `login` e `logout` em [`core/urls.py`](../../../core/urls.py).

2. **Permissões por Perfil — RBAC Nativo (Item 0.2):**
   * Adicionadas permissões customizadas no modelo [`ProcessoOffboarding`](../../../apps/governance/models.py): `iniciar_offboarding` e `revogar_item_offboarding`.
   * Criada a data migration [`0003_create_default_rbac_groups.py`](../../../apps/governance/migrations/0003_create_default_rbac_groups.py), garantindo a criação consistente dos 3 grupos corporativos:
     * **`Auditor`:** Somente leitura de colaboradores, sistemas, matriz e processos + emissão de relatórios.
     * **`Analista TI`:** Permissões do Auditor + início de offboarding e revogação técnica de acessos no checklist.
     * **`Gestor SecOps`:** Permissões totais de administração, cadastro e reabertura.
   * Aplicado `PermissionRequiredMixin` nas Class-Based Views e `@permission_required(..., raise_exception=True)` nas views funcionais em [`apps/governance/views.py`](../../../apps/governance/views.py).

3. **Eliminação de Usuário Automático / Fallback (Item 0.3):**
   * Removido qualquer fallback automático que criava usuários silenciosamente ou atribuía ações a terceiros.
   * **Não-Repúdio Estrito:** O responsável gravado nas tabelas de auditoria (`ProcessoOffboarding.responsavel_ti`, `ItemChecklistOffboarding.responsavel_revogacao`, `VinculoAcesso.revogado_por`) é estritamente `request.user`.

4. **Neutralização de Stored XSS no `onclick` (Item 0.4):**
   * Removido o JavaScript inline `onclick="return confirm(...)"` em [`templates/governance/colaborador_detail.html`](../../../templates/governance/colaborador_detail.html).
   * Implementado o desacoplamento via atributo `data-confirm` e script externo [`static/js/app.js`](../../../static/js/app.js).
   * Essa separação elimina a possibilidade de injeção de código via nomes de colaboradores e viabiliza a futura ativação de CSP rígida sem `unsafe-inline`.

5. **Remoção de Senha Fixa no Seed (Item 0.5):**
   * Removida a criação de superusuário com senha estática em [`apps/governance/management/commands/seed_governance.py`](../../../apps/governance/management/commands/seed_governance.py).
   * Implementada trava de segurança que recusa a execução do `seed_governance` caso `DEBUG=False`.

6. **Acesso Master / Root de Desenvolvimento:**
   * Criado o comando dedicado [`apps/governance/management/commands/create_root.py`](../../../apps/governance/management/commands/create_root.py) (`python manage.py create_root`).
   * Provisiona a conta master `root` com privilégios de superusuário e associação ao grupo `Gestor SecOps` para testes e desenvolvimento do sistema, com trava estrita de recusa em produção (`DEBUG=False`).

---

## 2. 🧪 Validação Automatizada de Segurança

Atualizada a suíte em [`apps/governance/tests.py`](../../../apps/governance/tests.py) com testes específicos para a Fase 0:
* `test_01_autenticacao_obrigatoria_redireciona_anonimos`: Redirecionamento 302 para login em todas as rotas.
* `test_02_tela_de_login_disponivel_sem_autenticacao`: Disponibilidade pública da tela de login e proteção CSRF.
* `test_03_segregacao_funcoes_auditor_apenas_leitura`: Auditor visualiza painéis, mas recebe 403 Forbidden ao tentar iniciar offboarding.
* `test_04_analista_ti_executa_offboarding_com_nao_repudio_estrito`: Analista executa offboarding e seu ID é gravado com não-repúdio.
* `test_05_neutralizacao_stored_xss_data_confirm`: Payload malicioso de XSS não é inserido em manipuladores executáveis.
* `test_06_master_root_acesso_total`: Validação de acesso universal irrestrito da conta master `root`.

**Resultado dos testes:**
```text
Ran 6 tests in 8.283s - OK (100% aprovado)
```

---

## 3. 📋 Próximo Passo

Avançar para a **Fase 1 (Integridade da Auditoria & Regras de Negócio)** do Plano de Ação:
* Substituir `CASCADE` por `PROTECT` nos modelos de vínculo e offboarding.
* Adicionar `django-simple-history` para rastreamento de versões.
* Implementar camada de serviço transacional `services.revogar_item()`.
* Exigir evidência obrigatória para sistemas críticos/LGPD.
