# 🏗️ Diário Oficial de Segurança — Fase 8: Infraestrutura & Deploy Seguro

**Data:** 05/11/2026  
**Status:** Concluído e Validado  
**Frameworks:** CIS Controls v8 (3.3, 4.1, 5.5, 11.1, 11.2, 11.4) | MITRE ATT&CK (T1552, T1565) | OWASP A05:2021  
**Módulos Afetados:** [`docker-compose.yml`](../../docker-compose.yml), [`Caddyfile`](../../Caddyfile), [`.dockerignore`](../../.dockerignore), [`.gitignore`](../../.gitignore), [`scripts/backup_db.sh`](../../scripts/backup_db.sh), [`core/settings.py`](../../core/settings.py), [`.env.example`](../../.env.example), [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), [`.github/dependabot.yml`](../../.github/dependabot.yml)

---

## 1. Contexto & Vetores de Ameaça Mitigados

A infraestrutura e os scripts de apoio foram endurecidos com base no princípio *Fail-Closed* e no isolamento de privilégios:

1. **Credenciais Padrão no Docker Compose (🟠 Alto):**
   - Senhas e chaves secretas com valores de fallback permitiam inicializar contêineres de produção vulneráveis caso o `.env` fosse esquecido.
2. **Exposição Direta da Porta da Aplicação sem TLS (🟡 Médio):**
   - `SECURE_PROXY_SSL_HEADER` estava ativo globalmente, abrindo brecha para que qualquer cliente forjasse `X-Forwarded-Proto: https` diretamente na porta 8000 exposta.
3. **Vazamento de Dumps e Backups em Imagens Docker (🟠 Alto):**
   - O `.dockerignore` baseado em blocklist permitia que novos artefatos sensíveis (como dumps gerados pelo script de backup) fossem copiados para a imagem durante o `COPY . .`.
4. **Criptografia Simétrica Fraca no Backup (🔵 Baixo):**
   - Senhas passadas via CLI (`-pass pass:`) expostas na tabela de processos do SO; arquivos intermediários descriptografados gravados em disco.
5. **HSTS Agressivo Global (🟡 Médio):**
   - `SECURE_HSTS_PRELOAD` e `INCLUDE_SUBDOMAINS` ativos por default podiam derrubar outros subdomínios da empresa sem HTTPS.

---

## 2. Implementações Técnicas

### 2.1 Compose Fail-Closed & Proxy Reverso Caddy
- Em [`docker-compose.yml`](../../docker-compose.yml):
  - Variáveis sensíveis convertidas para a sintaxe obrigatória: `${SECRET_KEY:?defina SECRET_KEY no .env}` e `${POSTGRES_PASSWORD:?defina POSTGRES_PASSWORD no .env}`.
  - Imagem PostgreSQL fixada em `postgres:16.8-alpine`.
  - Serviço `caddy` adicionado (`caddy:2.9.1-alpine`), expondo 80 e 443 na rede pública e gerenciando certificados TLS automaticamente.
  - Serviço `web` isolado da rede pública com `expose: ["8000"]` (somente acessível internamente pelo Caddy).
  - Parâmetros `TRUSTED_PROXY_COUNT: "1"` e `USE_X_FORWARDED_PROTO: "True"` injetados no serviço web.
- Em [`Caddyfile`](../../Caddyfile):
  - Proxy reverso com limpeza de cabeçalhos de clientes externos e injeção do IP de borda real.

### 2.2 Política de Allowlist no `.dockerignore` & `.gitignore`
- Em [`.dockerignore`](../../.dockerignore):
  - Adotada a política **Negar por Padrão**: inicializado com `*`, seguido de exceções estritas (`!apps/`, `!core/`, `!templates/`, `!static/`, etc.). Nenhum arquivo ou diretório novo pode entrar na imagem do contêiner sem liberação explícita.
- Em [`.gitignore`](../../.gitignore):
  - Adicionadas regras para `backups/`, `*.sql.gz`, `*.dump`, `*.age` e `*.enc`.

### 2.3 Backup Assimétrico com `age` (Chave Pública)
- Em [`scripts/backup_db.sh`](../../scripts/backup_db.sh):
  - Exigência fail-closed de chave pública em `BACKUP_AGE_RECIPIENT:?`.
  - Streaming em pipe contínuo: `pg_dump --format=custom | age -r "${BACKUP_AGE_RECIPIENT}" > ...`.
  - **Zero arquivos em texto claro no disco** e **zero credenciais expostas na CLI**.
  - O servidor detém apenas a chave de *cifra*; a chave de *decifra* permanece offline e protegida.

### 2.4 HSTS Gradual & Hardening de CI/CD
- Em [`core/settings.py`](../../core/settings.py):
  - `SECURE_HSTS_PRELOAD` e `SECURE_HSTS_INCLUDE_SUBDOMAINS` desativados por padrão (`False`).
  - `USE_X_FORWARDED_PROTO` condiciona `SECURE_PROXY_SSL_HEADER` apenas quando proxy reverso estiver ativo.
- Em [`.env.example`](../../.env.example):
  - Linhas que desativam cookies seguros foram comentadas com notas explicativas.
- Em [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) e [`.github/dependabot.yml`](../../.github/dependabot.yml):
  - Ações do GitHub fixadas por commit SHA imutável.
  - Ecossistema `github-actions` adicionado ao Dependabot.
  - Etapa automatizada de verificação de fail-closed do Docker Compose no pipeline.

---

## 3. Validação & Testes Automatizados

- `test_81_docker_compose_fail_closed_sem_senhas_default`: Garante sintaxe `:?` e ausência de senhas padrão.
- `test_82_proxy_reverso_caddy_e_x_forwarded_proto`: Valida isolamento de rede do compose, existência do Caddyfile e condicionalidade do SSL header.
- `test_83_dockerignore_allowlist_e_gitignore_backups`: Comprova allowlist `*` e bloqueio de backups no Git.
- `test_84_script_backup_usa_age_chave_publica`: Valida chave assimétrica sem intermediários no disco.
- `test_85_hsts_conservador_por_padrao`: Comprova defaults seguros de HSTS.
- `test_86_env_example_e_dependabot_actions`: Comprova integridade de documentação e CI/CD.

