# 🛡️ Diário de Bordo: 2026-11-05 - Plano v2: Fase 5: Fechamento de Portas & Catraca RBAC

* **Data:** 05 de Novembro de 2026
* **Projeto:** GateKeeper-DBF (Central de Governança de Acessos & Offboarding Seguro)
* **Autor / Responsável:** David B. F.
* **Origem:** Implementação da Fase 5 do Plano de Ação v2 (Brechas Pós-Implementação)
* **Fase:** Fase 5 — Emergência: Fechamento das Portas de Entrada
* **Status:** ✅ Concluída

---

## 1. 🔍 Resumo Executivo & Severidade

* **Classificação de Severidade Residual:** `[BAIXA / CONTROLADA]` (Eliminado o vetor de autocadastro público e blindada a superfície de visualização do dashboard executivo contra usuários não autorizados).
* **Mapeamento Normativo:**
  * **CIS Controls v8:**
    * Salvaguarda 5.1 (*Establish and Maintain an Inventory of Accounts*): Contas restritas estritamente ao provisionamento institucional.
    * Salvaguarda 5.3 (*Disable Dormant Accounts*): Auditoria ativa e desativação preventiva de credenciais órfãs via CLI.
    * Salvaguarda 6.5 (*Require MFA for Administrative Access*): Obrigatoriedade de TOTP para perfis com permissão de escrita.
  * **ISO/IEC 27001:2022:** A.9.2 (*User Access Provisioning*) e A.9.4 (*Access Control*).
  * **OWASP Top 10 (A01:2021 - Broken Access Control):** Eliminação de bypass em views executivas e imposição do princípio *Deny by Default*.

* **O que foi implementado:**
  A conclusão da Fase 5 fecha as portas de entrada que permaneceram expostas por padrões permissivos de bibliotecas terceiras:
  1. **Desativação de Signup:** Implementado `NoSignupAccountAdapter` no django-allauth, impedindo requisições `POST /accounts/signup/` de provisionarem usuários anonimamente;
  2. **Proteção do Dashboard Executivo:** Adicionado `PermissionRequiredMixin` com `governance.view_colaborador` na `DashboardView`;
  3. **Teste-Catraca de Rotas:** Implementado teste automatizado que varre 100% das rotas de URL do módulo de governança exigindo resposta `HTTP 403 Forbidden` para qualquer usuário autenticado sem grupos atribuídos, falhando no CI se novas rotas forem criadas sem registro no teste;
  4. **MFA Mandatório para Escrita:** Criado `RequireMFAMiddleware` forçando operadores com permissão de escrita (*Analista TI*, *Gestor SecOps*, *Staff*) a cadastrar TOTP antes de acessar o sistema;
  5. **Comando de Auditoria:** Criado comando de gestão `python manage.py auditar_contas --desativar` para identificação e saneamento preventivo de contas no banco.

---

## 2. 🎯 Mapeamento MITRE ATT&CK

| Tática | Técnica | ID | Mitigação no GateKeeper-DBF |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Valid Accounts: Local Accounts | `T1078.003` | `NoSignupAccountAdapter` proíbe o registro anônimo de novas contas pela internet. |
| **Discovery** | Account Discovery / System Information Discovery | `T1087 / T1082` | `DashboardView` exige `governance.view_colaborador`, impedindo visualização de contas órfãs e sistemas por visitantes sem perfil. |
| **Lateral Movement** | Use Alternate Authentication Material | `T1550` | `RequireMFAMiddleware` impõe segundo fator (TOTP) para contas privilegiadas, mitigando uso indevido de senhas vazadas. |
| **Defense Evasion** | Impair Defenses: Disable Accounts | `T1562` | Saneamento ativo com `python manage.py auditar_contas` e trilha de auditoria SOC (`ACCOUNT_DEACTIVATED_BY_AUDIT`). |

---

## 3. 🛠️ Arquivos Criados e Modificados

* [`apps/governance/adapters.py`](../../apps/governance/adapters.py): Adapter customizado com `is_open_for_signup(request) -> False`.
* [`templates/account/signup_closed.html`](../../templates/account/signup_closed.html): Template Dark SOC com aviso de cadastro desativado por política corporativa.
* [`apps/governance/middleware.py`](../../apps/governance/middleware.py): Middleware `RequireMFAMiddleware` interceptando perfis com privilégio de escrita sem TOTP.
* [`apps/governance/management/commands/auditar_contas.py`](../../apps/governance/management/commands/auditar_contas.py): Utilitário de auditoria e contenção CLI.
* [`core/settings.py`](../../core/settings.py): Configuração de `ACCOUNT_ADAPTER` e registro do middleware na pipeline.
* [`apps/governance/views.py`](../../apps/governance/views.py): Imposição de `PermissionRequiredMixin` na `DashboardView`.
* [`apps/governance/tests.py`](../../apps/governance/tests.py): Inclusão da classe `Phase5EmergencyEntryProtectionTests` com 5 testes de segurança automatizados.

---

## 4. 🧪 Validação dos Testes

* **Total de Testes Automatizados:** 29 testes (5 novos testes na Fase 5).
* **Resultado:** `OK` (100% aprovados em ~39s).
* **Cobertura de Código:**
  * `apps/governance/adapters.py`: **100%**
  * `apps/governance/middleware.py`: **100%**
  * `apps/governance/services.py`: **98%**
  * `apps/governance/views.py`: **85%**
  * Média do módulo: **88%** (acima da meta de $\ge 85\%$).

