# 🛡️ Diário Oficial de Segurança — Fases 13 a 17: CI, Modularização de Testes, Revisão Periódica e Ciclo de Vida de Acessos (Plano v4)

**Data:** 06/11/2026
**Status:** Concluído e Validado
**Frameworks de Referência:** MITRE ATT&CK (T1078 - Valid Accounts, T1098 - Account Manipulation, T1565 - Data Manipulation, T1204 - User Execution) | CIS Controls v8 (5.3, 5.5, 6.5, 6.8, 16.3) | OWASP Top 10 (A01: Broken Access Control, A03: Injection, A04: Insecure Design, A05: Security Misconfiguration) | NIST SP 800-61 Rev. 2
**Módulos Afetados:** [`apps/governance/models.py`](../../apps/governance/models.py), [`apps/governance/services.py`](../../apps/governance/services.py), [`apps/governance/admin.py`](../../apps/governance/admin.py), [`apps/governance/views.py`](../../apps/governance/views.py), [`apps/governance/tests/`](../../apps/governance/tests/), [`apps/governance/management/commands/`](../../apps/governance/management/commands/), [`core/settings.py`](../../core/settings.py), [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), [`.github/dependabot.yml`](../../.github/dependabot.yml)

---

## 1. Contexto & Vetores de Ameaça Mitigados

Com a conclusão das Fases 0 a 12, o GateKeeper-DBF já operava com autenticação multifator (TOTP), proteção contra força bruta, rate limiting compartilhado via banco de dados e trilhas de auditoria protegidas contra tamper. No entanto, auditorias de segurança e boas práticas de IAM (Identity and Access Management) identificaram vulnerabilidades de governança e operação:

1. **Acúmulo Excessivo de Acessos (*Privilege Creep* - MITRE T1078 / CIS Controls 5.3 & 6.8):**
   - Colaboradores acumulavam permissões de setores e funções anteriores por ausência de um processo formal e periódico de recertificação de acessos.
   - Mudanças de departamento ocorriam sem revisão obrigatória dos acessos prévios.
2. **Ausência de Segregação de Funções na Gestão de Acessos (OWASP A01 / Four-Eyes Principle):**
   - Usuários poderiam aprovar os próprios acessos caso a catraca de autorização não implementasse validação estrita no nível de objeto e no domínio de serviços.
3. **Riscos de Injeção de Fórmulas e Inconsistências em Cargas em Lote (OWASP A03 / MITRE T1204):**
   - A importação de colaboradores a partir de planilhas de RH poderia introduzir caracteres maliciosos (`=`, `+`, `-`, `@`) exploráveis em ferramentas de planilha (CSV Formula Injection) ou provocar desligamentos involuntários por ausência de registros no CSV.
4. **Vazamento de Dados Pessoais e Credenciais em Canais Inseguros (LGPD Art. 46 / CIS Controls 5.5):**
   - Envio de notificações de governança por e-mail contendo listas de acessos, nomes de sistemas e identificadores corporativos, suscetíveis à interceptação em trânsito.
5. **Déficit de Visibilidade de SLA em Processos de Desligamento:**
   - Ausência de cálculo formal de tempo decorrido entre o pedido de desligamento e a revogação efetiva, impossibilitando a medição do cumprimento da meta corporativa de 24 horas.
6. **Fragridades no Pipeline de CI e Dívida Técnica em Testes:**
   - Falhas no `gitleaks-action` por indefinição de versão e dependências de CI permissivas.
   - Suíte de testes monolítica (`tests.py` com mais de 1.800 linhas), dificultando a manutenção e a identificação de regressões.

---

## 2. Implementações Técnicas

### 2.1 Fase 13 — CI Confiável & Governança de Dependências
- **Ajuste do Gitleaks no GitHub Actions ([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)):**
  - Removido `fetch-depth: 0` do step anterior e fixada a versão oficial do runner `gitleaks-action@v8.21.2` (commit `9452c4a`).
- **Modernização de Runner e Privilégios Mínimos:**
  - Atualizado para `runs-on: ubuntu-24.04` e declarado o bloco estrito `permissions: contents: read` no topo do workflow.
- **Agrupamento de Dependências no Dependabot ([`.github/dependabot.yml`](../../.github/dependabot.yml)):**
  - Criados grupos `production-dependencies` e `dev-dependencies` para atualizações agrupadas de minor e patch, reduzindo ruído de PRs.

### 2.2 Fase 14 — Modularização da Suíte de Testes
- **Decomposição Modular de `tests.py`:**
  - Pacote [`apps/governance/tests/`](../../apps/governance/tests/) criado e dividido em 8 módulos temáticos:
    - `base.py`: Fixtures compartilhadas (`setup_fase10_fixtures`), clientes autenticados e helpers de teste.
    - `test_autenticacao.py`: Fluxos de login, MFA (TOTP), bloqueio e rate limiting.
    - `test_autorizacao.py`: Catraca de permissões, isolamento de papéis (RBAC) e proteção de histórico no Django Admin.
    - `test_offboarding.py`: Máquina de estados finita de desligamento, concorrência e evidências.
    - `test_admin.py`: Hardening de interface de administração e mixins somente leitura.
    - `test_auditoria.py`: Emissão de eventos estruturados em JSON para o SOC/SIEM.
    - `test_deploy.py`: Validações de system checks (`check --deploy`) e segurança em produção.
    - `test_frontend.py`: Conformidade estrita de CSP (ausência de scripts e estilos inline).
  - Mantidos todos os 85 testes originais com 97% de cobertura preservada (commit `dabe000`).

### 2.3 Fase 15 — Revisão Periódica de Acessos
- **Vínculos de Identidade e Modelagem ([`apps/governance/models.py`](../../apps/governance/models.py)):**
  - Campo `Colaborador.usuario` associando o colaborador à sua conta `User` do Django, com desativação automática (`is_active = False`) no desligamento.
  - Campo `Sistema.dono` designando o responsável técnico/negocial pelo sistema.
  - Modelos `CampanhaRevisao` e `ItemRevisao` criados com `HistoricalRecords()`, `PROTECT` nas chaves estrangeiras e integridade referencial estrita (migrações `0008` e `0009`).
- **Serviços de Domínio & Segregação de Funções ([`apps/governance/services.py`](../../apps/governance/services.py)):**
  - `abrir_campanha`: Gera fotografia estática (`freeze`) de todos os vínculos de acesso ativos no momento da criação.
  - `escolher_revisor`: Algoritmo hierárquico (gestor do colaborador ➔ dono do sistema ➔ criador da campanha).
  - **Segregação Estrita (Four-Eyes):** Colaborador nunca aprova a revisão do próprio acesso (`usuario.id == vinculo.colaborador.usuario_id` lança `PermissionDenied`).
  - **Proteção contra IDOR:** Visualização e decisão de itens por usuários não atribuídos retorna estritamente `HTTP 404 Not Found`.
  - `concluir_revogacao_ti`: Itens com decisão `REVOGAR` geram tarefa de desprovisionamento pela TI, exigindo evidência técnica obrigatória e desativando o `VinculoAcesso`.
- **Telas e Interface Responsiva:**
  - `campanha_list.html`, `campanha_abrir.html`, `campanha_painel.html`, `campanha_relatorio.html` e `minhas_revisoes.html`.
  - Conformidade estrita de Content Security Policy (CSP): zero tags `<style>` ou atributos `style="..."`, zero manipuladores `onclick`/`onsubmit` inline, uso de barras de progresso semânticas `<progress class="gk-progress ...">` e listeners desacoplados em `static/js/app.js`.

### 2.4 Fase 16 — Operação, SLAs e Ferramentas Seguras
- **Métricas de SLA de Offboarding ([`apps/governance/models.py`](../../apps/governance/models.py)):**
  - Configurado `OFFBOARDING_SLA_HORAS = 24` em `core/settings.py`.
  - Properties `tempo_ate_revogacao_horas` e `acima_do_sla` em `ProcessoOffboarding`.
  - Indicadores executivos no Painel de Controle e no Relatório de Auditoria: mediana do tempo de resposta, pior caso registrado e percentual de processos acima do SLA.
- **Lembretes Operacionais Seguros ([`apps/governance/management/commands/enviar_lembretes.py`](../../apps/governance/management/commands/enviar_lembretes.py)):**
  - Comando `enviar_lembretes` para notificar gestores e equipe de TI sobre ações pendentes.
  - **Privacy by Design:** O corpo do e-mail não contém dados pessoais, nomes de contas ou credenciais; envia estritamente o link corporativo seguro do GateKeeper, exigindo login com MFA. Log auditável `ALERT_REMINDERS_SENT`.
- **Importação Segura de RH ([`apps/governance/management/commands/importar_colaboradores.py`](../../apps/governance/management/commands/importar_colaboradores.py)):**
  - Comando `importar_colaboradores` com suporte a `--simular` (dry-run padrão) e `--aplicar`.
  - **Mitigação de CSV Formula Injection:** Função `sanitizar_celula_csv` neutraliza caracteres perigosos (`=`, `+`, `-`, `@`, `\t`, `\r`) prefixando apóstrofo (`'`).
  - **Princípio da Não-Destrutividade:** Colaboradores ausentes no CSV não são desligados automaticamente; são sinalizados como "a verificar" no relatório e no evento estruturado `HR_IMPORT`. Transação única atômica (`transaction.atomic`).

### 2.5 Fase 17 — Ciclo de Vida Completo de Acessos
- **Fluxo Formal de Entrada e Concessão:**
  - Modelo `SolicitacaoAcesso` rastreando justificativa de negócio, chamado/ticket ITSM, solicitante, aprovador e evidência técnica de concessão pela TI.
  - Funções de domínio `solicitar_acesso`, `aprovar_solicitacao` e `conceder_acesso`:
    - Segregação de funções estrita: quem solicita nunca aprova a própria solicitação; quem aprova não é quem concede/provisiona na TI.
    - O vínculo `VinculoAcesso` só é criado/ativado após concessão formal com evidência.
- **Pacotes de Acesso por Cargo (Perfis Padrão):**
  - Campo Many-to-Many `Cargo.perfis_padrao` permitindo definir o perfil mínimo de menor privilégio concedido a cada função, evitando desvios por cópia de permissões.
- **Mini-Revisão de Mudança de Cargo (*Role Change Review*):**
  - Função `alterar_cargo_colaborador`: Ao transferir um colaborador de cargo ou departamento, o sistema atualiza o cadastro e deflagra automaticamente uma mini-campanha de revisão com prazo estrito (7 a 15 dias) para reavaliação de todos os acessos anteriormente concedidos.

---

## 3. Mapeamento MITRE ATT&CK & Trilha de Auditoria

| Técnica MITRE ATT&CK | Descrição da Ameaça | Mecanismo de Defesa & Detecção no GateKeeper |
|---|---|---|
| **T1078 - Valid Accounts** | Uso indevido de contas válidas e acúmulo de acessos obsoletos | Fotografia e revisão periódica periódica (`CampanhaRevisao`); mini-revisão automática na mudança de cargo; expiração via SLA de 24h no offboarding. |
| **T1098 - Account Manipulation** | Concessão arbitrária ou não autorizada de privilégios | Fluxo de três vias (`SolicitacaoAcesso`): Solicitação ➔ Aprovação (Dono/Gestor) ➔ Concessão (TI), com Four-Eyes Principle. |
| **T1204 - User Execution** | Execução de fórmulas maliciosas em planilhas abertas por operadores | Sanitização ativa de células (`sanitizar_celula_csv`) contra injeção de fórmulas CSV (`=`, `+`, `-`, `@`). |
| **T1565 - Data Manipulation** | Adulteração de trilhas e históricos de decisões de acesso | `HistoricalRecords()` em todos os modelos; Django Admin somente leitura (`SomenteLeituraAdminMixin` e `HistoricoSomenteLeituraAdmin`). |

### Eventos de Auditoria Emitidos para o SOC / SIEM:
- `REVIEW_CAMPAIGN_OPENED`: Abertura formal de campanha com quantidade de vínculos congelados e prazos.
- `REVIEW_DECISION`: Registro atômico de decisão de manter ou revogar com justificativa e revisor.
- `REVIEW_REVOCATION_EXECUTED`: Confirmação técnica de desprovisionamento pela TI com chamado e evidência.
- `ALERT_REMINDERS_SENT`: Notificações operacionais emitidas com respeito a privacidade.
- `HR_IMPORT`: Relatório atômico de sincronização de cadastro de RH.
- `ACCESS_REQUEST_CREATED`, `ACCESS_REQUEST_APPROVED`, `ACCESS_GRANTED`: Ciclo de concessão formal de privilégios.
- `ROLE_CHANGE_MINI_REVIEW`: Disparo de reavaliação mandatória de acessos na transferência de função.

---

## 4. Matriz de Testes Automatizados & Resultados

A suíte de testes completa foi executada com 100% de aprovação e sem regressões:

```bash
Found 101 test(s).
Creating test database for alias 'default'...
...
Ran 101 tests in 144.156s
OK
```

### Resumo da Cobertura de Testes:
- **Total de Testes:** 101 testes automatizados (85 originais + 10 de Revisão de Acessos + 6 de Operação e Ciclo de Vida).
- **Cobertura Global de Código:** **91%** de cobertura real nos módulos de negócio e segurança.
- **Linters & Qualidade:**
  - `ruff check .`: 100% aprovado (0 erros).
  - `ruff format --check .`: 100% aprovado e formatado.
  - `bandit -c pyproject.toml -r apps core`: 0 vulnerabilidades identificadas.
  - `pre-commit run --all-files`: Todos os 8 hooks (`ruff`, `gitleaks`, `yaml`, `end-of-file`, `whitespace`, `tailwind`) aprovados com sucesso.
