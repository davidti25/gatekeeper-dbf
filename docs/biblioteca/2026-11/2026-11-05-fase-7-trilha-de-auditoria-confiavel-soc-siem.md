# 🔎 Diário Oficial de Segurança — Fase 7: Trilha de Auditoria Confiável (SOC / SIEM)

**Data:** 05/11/2026  
**Status:** Concluído e Validado  
**Frameworks:** CIS Controls v8 (8.2, 8.5) | MITRE ATT&CK (T1070, T1110) | CWE-117 | CWE-345  
**Módulos Afetados:** [`apps/governance/utils.py`](../../apps/governance/utils.py), [`apps/governance/logging.py`](../../apps/governance/logging.py), [`apps/governance/signals.py`](../../apps/governance/signals.py), [`apps/governance/services.py`](../../apps/governance/services.py), [`core/settings.py`](../../core/settings.py)

---

## 1. Contexto & Vetores de Ameaça Mitigados

A integridade da trilha de auditoria é a base para qualquer resposta a incidentes (IR / NIST SP 800-61). Na arquitetura inicial, foram identificadas duas brechas de telemetria:

1. **IP Spoofing via `X-Forwarded-For` (CWE-345 / 🟡 Médio):**
   - O sinal de auditoria consumia o **primeiro** IP da cadeia de `X-Forwarded-For`.
   - Como qualquer cliente HTTP pode injetar cabeçalhos arbitrários, um atacante em força bruta (MITRE `T1110`) podia forjar IPs nos alertas do SOC (ex: atribuindo a falha a um IP interno ou de parceiro).
2. **Log Injection / Splitting (CWE-117 / 🟡 Médio):**
   - Os eventos eram montados via interpolação de strings (`f-strings`) contendo entradas do usuário (evidências, motivos, usuários de login).
   - A injeção de caracteres de quebra de linha (`\r\n`) permitia forjar falsas entradas de log no SIEM (ex: injetando falsos eventos `AUTH_LOGIN_SUCCESS`).

---

## 2. Implementações Técnicas

### 2.1 Sanitização do IP do Cliente (`get_client_ip`)
Implementado em [`apps/governance/utils.py`](../../apps/governance/utils.py):
- **Estratégia da Direita para a Esquerda (`cadeia[-n]`):** Cada proxy reverso sob controle da organização acrescenta o IP de quem se conectou a ele no final da cadeia. O que está à esquerda pode ser forjado pelo cliente; o que está à direita, na profundidade correspondente aos proxies controlados, é autêntico.
- **Fail-Closed por Padrão:** `TRUSTED_PROXY_COUNT = env.int("TRUSTED_PROXY_COUNT", default=0)` em [`core/settings.py`](../../core/settings.py). Sem proxies declarados, `X-Forwarded-For` é estritamente ignorado e `request.META["REMOTE_ADDR"]` é utilizado.
- **Integração com Django-Allauth:** Configurado `ALLAUTH_TRUSTED_PROXY_COUNT = TRUSTED_PROXY_COUNT` para manter a precisão do rate limiting do allauth.

### 2.2 Formatador Nativo JSON (`JSONAuditFormatter`)
Implementado em [`apps/governance/logging.py`](../../apps/governance/logging.py):
- **Serialização Estrita:** Utiliza `json.dumps(payload, ensure_ascii=False, default=str)` para serializar todos os campos.
- **Escape Automático de Delimitadores:** Caracteres `\r`, `\n` e aspas são escapados automaticamente na string JSON, garantindo a invariante: **um evento de log corresponde estritamente a uma única linha física**.
- **Refatoração dos Emissores:**
  - Sinais de autenticação (`AUTH_LOGIN_SUCCESS`, `AUTH_LOGOUT`, `AUTH_LOGIN_FAILED [MITRE T1110]`);
  - Ciclo de vida de offboarding (`OFFBOARDING_PROCESS_INITIATED`, `OFFBOARDING_ITEM_REVOKED`, `OFFBOARDING_PROCESS_CONCLUDED`);
  - Comando de auditoria preventiva (`ACCOUNT_DEACTIVATED_BY_AUDIT`).
  Todos passaram a utilizar `extra={"audit": {...}}`.

---

## 3. Validação & Testes Automatizados

- `test_71_ip_real_com_proxy_e_sem_proxy`: Valida isolamento com 0, 1 e 2 proxies, além de requisições nulas ou cadeias curtas.
- `test_72_json_audit_formatter_anti_log_injection`: Injeta payload malicioso com `\r\n` simulando ataque de Log Injection e comprova que a saída contém exatamente 0 quebras de linha (`\n` e `\r`).
- `test_23_trilha_auditoria_soc_sinais`: Validação ponta a ponta dos sinais de login/logout em formato JSON estruturado.

