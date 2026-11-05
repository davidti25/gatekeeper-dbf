# 🛡️ Diário Oficial de Segurança — Fases 10 a 12: Integridade, MFA, Infraestrutura & Deploy (Plano v3)

**Data:** 05/11/2026
**Status:** Concluído e Validado
**Frameworks:** MITRE ATT&CK (T1110 - Brute Force, T1078 - Valid Accounts) | CIS Controls v8 (3.3, 4.1, 5.5, 6.5, 8.2, 11.2) | OWASP Top 10 (A01: Broken Access Control, A04: Insecure Design, A05: Security Misconfiguration) | NIST SP 800-61 Rev. 2
**Módulos Afetados:** [`apps/governance/admin.py`](../../apps/governance/admin.py), [`apps/governance/apps.py`](../../apps/governance/apps.py), [`apps/governance/checks.py`](../../apps/governance/checks.py), [`apps/governance/middleware.py`](../../apps/governance/middleware.py), [`apps/governance/services.py`](../../apps/governance/services.py), [`apps/governance/signals.py`](../../apps/governance/signals.py), [`apps/governance/tests.py`](../../apps/governance/tests.py), [`core/settings.py`](../../core/settings.py), [`docker-compose.yml`](../../docker-compose.yml), [`Caddyfile`](../../Caddyfile), [`scripts/backup_db.sh`](../../scripts/backup_db.sh)

---

## 1. Contexto & Vetores de Ameaça Mitigados

Após a conclusão dos Planos v1 e v2, uma terceira análise exaustiva de segurança identificou brechas residuais em integridade de identidade, resiliência de cache sob múltiplos workers, configuração de deploy e robustez de processos:

1. **Bypass de Regras de Negócio via Django Admin (A01 / CIS 4.1):**
   - O Django Admin permitia que usuários `is_staff` com privilégios de modelo editassem diretamente registros de `ProcessoOffboarding` e `ItemChecklistOffboarding`, ignorando a máquina de estados finita, a validação de evidências e o bloqueio de concorrência implementados no serviço de negócio.
   - Campos de rastreabilidade de vínculos (`concedido_por`, `revogado_por`, `data_concessao`, `data_revogacao`) estavam abertos para edição manual na interface de administração.
2. **Janela de Reuso Temporal de Códigos TOTP (RFC 6238 / CIS 6.5):**
   - Com tolerância de passos temporais (`MFA_TOTP_TOLERANCE > 0`), o `django-allauth` retém o código usado em cache apenas pelo período base (30 segundos). Após esse intervalo, a validação aceitava novamente o mesmo código em janelas adjacentes (+35s ou +65s). A tolerância padrão deve ser zero, restringindo descompassos a ambientes de desenvolvimento.
3. **Isolamento de Cache entre Workers e Processos Independentes (A04 / CIS 5.5):**
   - O uso de `LocMemCache` mantinha contadores de rate limiting e registros de tokens TOTP consumidos na memória de cada worker individual do Gunicorn. Requisições distribuídas permitiam contornar rate limits e revalidar códigos entre workers distintos.
4. **Força Bruta Distribuída contra Contas Alvo (MITRE T1110.001):**
   - A configuração de limitação de falhas de login operava apenas por IP (`5/5m`), desprotegida contra botnets ou proxies distribuídos atacando uma conta específica.
5. **Exigência de MFA por Permissão Efetiva:**
   - O middleware de obrigatoriedade de TOTP validava listas estáticas de nomes de grupos, abrindo brechas caso novos grupos de escrita fossem criados ou permissões fossem concedidas diretamente ao usuário.
6. **Robustez de Deploy, Backup e Cabeçalhos:**
   - Ausência de execução automática de `migrate` no compose gerava containers sem tabelas criadas.
   - O script de backup passava credenciais na linha de comando e não garantia atomicidade na geração de arquivos compactados e criptografados.
   - Cabeçalhos de CSP e HSTS exigiam refinamento estrito (`base-uri 'none'`, `object-src 'none'`, e HSTS sem `includeSubDomains` indiscriminado).

---

## 2. Implementações Técnicas

### 2.1 Fase 10 — Integridade & Identidade
- **Admin Read-Only para Offboarding (`apps/governance/admin.py`):**
  - Implementado `SomenteLeituraAdminMixin` aplicado a `ProcessoOffboardingAdmin`, `ItemChecklistOffboardingAdmin` e `ItemChecklistOffboardingInline`, bloqueando adições, edições e exclusões no Admin.
  - Em `VinculoAcessoAdmin`, os campos `concedido_por`, `revogado_por`, `data_concessao` e `data_revogacao` foram marcados como `readonly_fields` e são atribuídos automaticamente no `save_model()`.
  - Criada e executada a migração de dados `0006_remove_change_perms_from_analista_ti.py`, expurgando permissões de alteração desses modelos do grupo *Analista TI*.
- **Tolerância Zero de TOTP (`core/settings.py`):**
  - Configurado `MFA_TOTP_TOLERANCE = env.int("MFA_TOTP_TOLERANCE", default=0)` por padrão.
- **Cache Compartilhado via Banco de Dados (`core/settings.py`):**
  - Configurado `CACHES = {"default": env.cache("CACHE_URL", default="dbcache://gatekeeper_cache")}`.
  - Tabela `gatekeeper_cache` criada via `python manage.py createcachetable`.
- **Rate Limit Dual por IP e por Conta (`core/settings.py`):**
  - Configurado `ACCOUNT_RATE_LIMITS = {"login_failed": "10/m/ip,5/5m/key"}`.
- **Exigência de MFA por Permissão Efetiva (`apps/governance/middleware.py`):**
  - Implementada a função `exige_mfa(user)`, que avalia `user.is_staff`, `user.is_superuser` ou qualquer permissão não-leitura (`not perm.startswith("view_")`), integrando-a ao `RequireMFAMiddleware`.
- **System Checks de Deploy (`apps/governance/checks.py`):**
  - Registrados com `@register(Tags.security, deploy=True)`:
    - `gatekeeper.E001`: Trava `MFA_TOTP_TOLERANCE > 0` com `DEBUG=False`.
    - `gatekeeper.E002`: Trava `LocMemCache` ou `DummyCache` em produção.
    - `gatekeeper.E003`: Trava rate limit de login sem parâmetro `key`.
    - `gatekeeper.E004`: Trava uso de `MFA_TOTP_INSECURE_BYPASS_CODE` com `DEBUG=False`.

### 2.2 Fase 11 — Deploy & Infraestrutura
- **Serviço Migrate no Compose (`docker-compose.yml`):**
  - Serviço dedicado `migrate` com comando `python manage.py migrate --noinput && python manage.py createcachetable`. O serviço `web` depende de `condition: service_completed_successfully`.
- **HSTS Estrito sem Subdomínios (`Caddyfile`):**
  - Removido `includeSubDomains`, alinhando a política do Caddy com o Django.
- **Backup Atômico e Credenciais Seguras (`scripts/backup_db.sh`):**
  - Rejeita o uso de `DATABASE_URL` na linha de comando (`ps`).
  - Utiliza variáveis de ambiente padrão libpq (`PG*`) e `~/.pgpass`.
  - Gravação atômica em `${FINAL_FILE}.partial` com `trap 'rm -f "${PARTIAL_FILE}"' EXIT` e `mv` final apenas em caso de sucesso.
- **CSP Completa (`core/settings.py`):**
  - Adicionadas diretivas `"base-uri": ["'none'"]` e `"object-src": ["'none'"]`.

### 2.3 Fase 12 — Defesa em Profundidade, Testes & Processo
- **Autorização de "Não Aplicável" no Serviço (`apps/governance/services.py`):**
  - Validação de `not responsavel.has_perm("governance.marcar_nao_aplicavel")` levantando `PermissionDenied` diretamente na camada de serviço.
- **Log SOC com Captura de E-mail (`apps/governance/signals.py`):**
  - Captura `credentials.get("username") or credentials.get("email") or "DESCONHECIDO"` truncado em 150 caracteres para ingestão em SIEM.
- **Suíte de Testes de Regressão (`apps/governance/tests.py`):**
  - Criada a classe `Phase10To12IntegrityAndDeployTests` cobrindo integralmente os 12 testes especificados na Tabela 12.3.

---

## 3. Validação & Testes

- **75 testes automatizados aprovados (100% OK)** em 99.9 segundos.
- **Cobertura de código global de 93%** no módulo de governança.
- `bandit` security linter: 0 vulnerabilidades identificadas.
- `ruff check` e `ruff format`: 100% conformes.
- `manage.py check --deploy`: 0 erros de segurança identificados.
- Checklist de acompanhamento do plano integralmente validado e comprovado com nomes de testes unitários.

---

## 4. Revisão pós-implementação (05/11/2026)

Uma revisão do commit do Plano v3 encontrou quatro falhas residuais, todas corrigidas e cobertas pela classe `RevisaoPosPlanoV3Tests`:

| # | Severidade | Falha | Correção | Teste |
|---|---|---|---|---|
| R4 | **Alta** | A tela de versão do histórico do admin (`history_form_view`, django-simple-history 3.13) exigia só permissão de **leitura** e gravava o formulário num POST. Um usuário do grupo *Auditor* com acesso ao admin conseguia alterar status e observações de um processo de offboarding, contornando o admin somente leitura (10.1) e a máquina de estados. | Classe base `HistoricoSomenteLeituraAdmin`: histórico só para consulta (POST negado para todos, botão "Reverter" oculto). Todos os admins com histórico herdam dela. | `test_r4_historico_do_admin_nao_permite_gravar` (inclui varredura de todos os admins registrados) |
| R3 | Média | Vínculo **revogado** podia voltar a "Ativo" pelo admin, e o inline de vínculos na tela do colaborador permitia editar status e conceder acesso sem registrar `concedido_por`. | Vínculo revogado é somente leitura (estado final; reativar exige novo vínculo). Inline de vínculos virou só consulta, com link para a tela própria. | `test_r3_vinculo_revogado_e_somente_leitura_no_admin` |
| R1 | Média | Com o cache padrão em banco (`dbcache`), `migrate` não criava a tabela; fora do compose o rate limit do login falhava com `no such table`. | Migração `0007_criar_tabela_cache` executa `createcachetable`. | `test_r1_migrate_cria_tabela_de_cache` |
| R2 | Média | As checagens `gatekeeper.E001`–`E004` só rodavam no CI, nunca contra a configuração real de produção. | O serviço `migrate` roda `check --deploy --fail-level ERROR` antes de migrar; configuração insegura impede a subida do `web`. | `test_r2_compose_roda_check_deploy_antes_do_migrate` |

**Validação após a revisão:** 79 testes aprovados, cobertura de 93%, `ruff` e `bandit` sem apontamentos, `makemigrations --check` sem pendências.
