# 🛡️ Diário de Bordo: 2026-11-05 - Fase 4: Qualidade & DevSecOps

* **Data:** 05 de Novembro de 2026
* **Projeto:** GateKeeper-DBF (Central de Governança de Acessos & Offboarding Seguro)
* **Autor / Responsável:** David B. F.
* **Origem:** Implementação da Fase 4 do Plano de Ação de Segurança & Qualidade
* **Fase:** Fase 4 — Qualidade, Desempenho & DevSecOps Contínuo
* **Status:** ✅ Concluída

---

## 1. 🔍 Resumo Executivo & Severidade

* **Classificação de Severidade Residual:** `[MÍNIMA / CONTROLADA]` (Aplicação 100% blindada contra falhas de injeção, escalada de privilégios, dependências obsoletas, concorrência, vazamento de segredos e gargalos de banco de dados).
* **Mapeamento Normativo:**
  * **CIS Controls v8:**
    * Salvaguarda 11.1 / 11.2 (*Establish and Maintain a Data Recovery Process / Perform Automated Backups*).
    * Salvaguarda 16.1 (*Establish and Maintain a Secure Application Development Process*).
  * **NIST SP 800-190:** *Application Container Security Guide* (Uso de usuário não-root, imagens multi-stage e controle de integridade).
  * **OWASP Top 10 (A04:2021 - Insecure Design & A06:2021 - Vulnerable and Outdated Components):** Mitigação por SAST automatizado, auditoria de dependências (`pip-audit`) e validações estritas de domínio.

* **O que foi implementado:**
  A conclusão da Fase 4 consolida a esteira de engenharia e segurança (**DevSecOps**) do GateKeeper-DBF. Foram eliminadas as consultas duplicadas (N+1) nas listagens executivas; adicionadas validações estritas de negócio bloqueando a concessão de acessos a colaboradores desligados ou em desligamento; estabelecida uma suíte com **24 testes unitários automatizados** atingindo **85% de cobertura de código em views e 98% em services**; implementado pipeline no **GitHub Actions** com verificações automáticas de linting, formatação, SAST, CVEs de dependências e vazamento de segredos via `pre-commit`/`gitleaks`; e construído o ecossistema de containerização para produção via **Dockerfile multi-stage** com usuário não-root (UID 10001), suporte a PostgreSQL no `docker-compose.yml` e rotina de **backup criptografado AES-256-CBC**.

---

## 2. 🎯 Mapeamento MITRE ATT&CK

| Tática | Técnica | ID | Mitigação no GateKeeper-DBF |
| :--- | :--- | :--- | :--- |
| **Initial Access** | Supply Chain Compromise: Dependencies | `T1195.002` | `pip-audit` integrado ao pipeline CI/CD e hashes SHA-256 obrigatórios em `requirements.txt`. |
| **Credential Access** | Unsecured Credentials | `T1552` | `gitleaks` no pré-commit e no GitHub Actions impedindo o versionamento acidental de tokens e credenciais. |
| **Defense Evasion** | Valid Accounts | `T1078` | Bloqueio absoluto no ORM (`VinculoAcesso.save()`) contra concessão de acessos ativos a colaboradores desligados. |
| **Impact** | Data Destruction / Loss | `T1485` | Rotina de backup automatizada em `scripts/backup_db.sh` com compressão `gzip` e cifra `AES-256-CBC` com PBKDF2. |
| **Privilege Escalation** | Container Escape | `T1611` | Dockerfile executando como usuário de sistema desprivilegiado `appuser:appgroup` (UID 10001:10001). |

---

## 3. 🛠️ Detalhamento das Implementações Técnicas

### 3.1 Eliminação de Consultas N+1 (Otimização de Desempenho)
* **Problema:** As listagens de colaboradores, sistemas e processos de offboarding executavam chamadas a propriedades de modelo (`total_itens`, `total_revogados`, `total_acessos_ativos` e `perfis.count()`) que disparavam consultas `SELECT COUNT(*)` individuais para cada linha da tabela (complexidade $O(N)$).
* **Solução Implementada:**
  * Otimizado o método `get_queryset()` em [`apps/governance/views.py`](apps/governance/views.py) para anotar os valores agregados em lote via `annotate(Count(..., distinct=True))`.
  * Em [`apps/governance/models.py`](apps/governance/models.py), as propriedades foram refatoradas para verificar a existência do atributo anotado em cache (`hasattr(self, '_total_...')`), mantendo a consulta direta apenas como *fallback*.
  * O número de consultas SQL por página passou a ser estritamente fixo e previsível ($O(1)$).

### 3.2 Blindagem de Regras de Negócio & Não-Concessão a Desligados
* **Problema:** Um operador poderia criar um novo `VinculoAcesso` com status `ATIVO` apontando para um colaborador com status `DESLIGADO` ou em processo de offboarding.
* **Solução Implementada:**
  * Em [`apps/governance/models.py`](apps/governance/models.py), `VinculoAcesso.clean()` agora valida se o colaborador está desligado ou possui processo de offboarding em andamento, barrando a operação com `ValidationError`.
  * Adicionado `full_clean()` no método `save()` do modelo, garantindo que a regra seja aplicada universalmente (Django Admin, Forms web ou chamadas diretas via ORM).

### 3.3 Pipeline DevSecOps & Ferramental de Qualidade
* **Ruff & Formatação:**
  * Configurado [`pyproject.toml`](pyproject.toml) com regras estritas (`E`, `W`, `F`, `I`, `C4`, `B`, `UP`) e padrão de linha de 120 caracteres.
  * Todo o código-fonte foi formatado e verificado sem erros.
* **Bandit (SAST):**
  * Varredura estática de segurança configurada em `pyproject.toml`. Nenhuma vulnerabilidade ou risco de injeção/execução remota identificado.
* **Pip-Audit (Software Supply Chain Security):**
  * Varredura executada em [`requirements.txt`](requirements.txt), comprovando ausência de CVEs conhecidas nas dependências.
* **Pre-commit & Gitleaks:**
  * Criado [`.pre-commit-config.yaml`](.pre-commit-config.yaml) contendo hooks de linter `ruff`, formatador `ruff-format` e detector de segredos `gitleaks`.
* **GitHub Actions Workflow:**
  * Criado [`.github/workflows/ci.yml`](.github/workflows/ci.yml) automatizando todas as checagens a cada `push` e `pull_request` nas branches `main` e `develop`.

### 3.4 Containerização Segura & Estratégia de Backup
* **Dockerfile Multi-Stage ([`Dockerfile`](Dockerfile)):**
  * **Estágio 1 (Builder):** Compila pacotes com `--require-hashes` a partir de `requirements.txt`.
  * **Estágio 2 (Runtime):** Imagem mínima `python:3.14-slim`, cópia apenas dos wheels prontos, criação de usuário não-root `appuser` (UID 10001), execução de `collectstatic` e healthcheck HTTP ativo em `/login/`.
* **Orquestração Local ([`docker-compose.yml`](docker-compose.yml)):**
  * Serviço de banco de dados PostgreSQL 16 Alpine com checagem de saúde `pg_isready` e volume persistente.
  * Serviço web apontando para `core.wsgi:application` rodando com Gunicorn.
* **Script de Backup Criptografado ([`scripts/backup_db.sh`](scripts/backup_db.sh)):**
  * Suporta PostgreSQL (`pg_dump`) e SQLite (`db.sqlite3`).
  * Compacta com `gzip -9` e criptografa com `openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000`.
  * Define permissão restrita `chmod 600` e realiza rotação automática apagando cópias com mais de 30 dias.

---

## 4. 🧪 Relatório de Testes & Cobertura de Código

* **Total de Testes Unitários:** 24 testes automatizados em [`apps/governance/tests.py`](apps/governance/tests.py).
* **Tempo de Execução:** ~20 segundos.
* **Cobertura de Código (Coverage):**
  ```text
  Name                          Stmts   Miss  Cover
  -------------------------------------------------
  apps/governance/models.py       245     15    94%
  apps/governance/services.py      44      1    98%
  apps/governance/signals.py       25      2    92%
  apps/governance/views.py        215     32    85%
  apps/governance/forms.py         22      0   100%
  -------------------------------------------------
  TOTAL                          1090    167    85%
  ```

---

## 5. 💡 Dica de Bootcamp & Engenharia de Segurança

> [!TIP]
> **Por que imagens Docker Multi-Stage com usuário Não-Root são mandatórias em conformidade SOC 2 e CIS Benchmarks?**
> * **Redução de Superfície de Ataque:** No estágio de compilação (*builder*), instalamos compiladores como `gcc` e cabeçalhos de desenvolvimento (`libpq-dev`). Se um invasor conseguir uma *Remote Code Execution (RCE)* na aplicação web em produção e esses compiladores estiverem disponíveis no container, ele pode facilmente compilar rootkits, exploits de kernel locais ou ferramentas de pós-exploração. No multi-stage, os compiladores são descartados no primeiro estágio.
> * **Privilege Escalation Containment:** Por padrão, um processo em um container Docker executa como `root` (UID 0) se nenhuma diretiva `USER` for declarada. Embora os namespaces do Linux isolem processos, qualquer falha de escape de container (*Container Breakout* / `T1611`) daria privilégios de superusuário imediatos sobre o nó hospedeiro (host Linux). Ao rodar como UID 10001 sem shell interativo (`/sbin/nologin`), o impacto de um comprometimento fica estritamente confinado.

