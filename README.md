# GateKeeper-DBF 🛡️

> **Central de Governança de Acessos, Matriz RBAC & Gestão de Offboarding Seguro**
> *Desenvolvido e mantido por David B. F. • Engenharia de Cibersegurança & SecOps*

[![Licença: Apache-2.0](https://img.shields.io/badge/licen%C3%A7a-Apache--2.0-blue.svg)](LICENSE)

O GateKeeper-DBF registra **quem tem acesso a quê** na empresa e conduz o **desligamento de
colaboradores (offboarding)** até que todos os acessos estejam comprovadamente revogados, com
trilha de auditoria que não pode ser apagada nem editada.

---

## 🚨 O problema que ele resolve

1. **Contas órfãs.** Ex-colaboradores com VPN, e-mail, roteadores, bancos de dados ou SaaS ainda
   ativos — MITRE ATT&CK [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/).
2. **Acúmulo de privilégios (*privilege creep*).** Acessos que se somam conforme a pessoa muda de setor.
3. **Conformidade.** CIS Controls v8 (5.3 e 5.5), LGPD (Art. 46) e ISO 27001 (remoção de direitos
   de acesso) exigem evidência de que o acesso foi removido, por quem e quando.

## ✨ O que ele faz

- **Inventário:** colaboradores, departamentos, cargos, localidades, sistemas (com criticidade) e
  perfis de acesso.
- **Vínculos de acesso:** cada acesso concedido, com quem concedeu e quando.
- **Offboarding guiado:** ao desligar alguém, o sistema gera um checklist com todos os acessos
  ativos. Cada item exige evidência da revogação; "Não Aplicável" exige justificativa e permissão
  própria. O processo só conclui com 100% dos itens resolvidos.
- **Relatório de auditoria** do offboarding pronto para impressão.
- **Painel** com indicadores de acessos e processos em andamento.
- **Auditoria de contas:** `python manage.py auditar_contas` lista usuários sem perfil ou sem MFA.

## 🔒 Segurança

| Área | Controle |
|---|---|
| Acesso | Negado por padrão: toda página exige login e permissão. Um teste percorre todas as rotas e falha se alguma ficar desprotegida. |
| Identidade | MFA (TOTP) obrigatório para qualquer usuário que possa alterar dados; códigos não reutilizáveis; limite de tentativas de login por IP **e** por conta. |
| Integridade | Offboarding só muda pelo fluxo do sistema (transições controladas e travas de concorrência). Admin somente leitura para esses registros; histórico de versões de todos os modelos, sem exclusão. |
| Rastreabilidade | Logs de auditoria em JSON (login, falhas, revogações), prontos para SIEM. |
| Navegador | CSP rígida (sem script ou estilo inline), HSTS, cookies `Secure`/`HttpOnly`, proteção contra clickjacking. |
| Deploy | Compose não sobe sem segredos; `check --deploy` bloqueia configuração insegura antes de iniciar; backups criptografados com chave pública. |
| Processo | CI com lint, `bandit`, `pip-audit`, `gitleaks`, testes com cobertura mínima de 85% e dependências fixadas por hash. |

Encontrou uma vulnerabilidade? Veja a [Política de Segurança](SECURITY.md) — **não abra issue pública**.

---

## 🚀 Início rápido (desenvolvimento)

Requisitos: **Python 3.14** e Git.

```bash
git clone https://github.com/davidti25/gatekeeper-dbf.git
cd gatekeeper-dbf
python3.14 -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt   # versões fixadas e verificadas por hash

cp .env.example .env
# Edite o .env: defina SECRET_KEY (o próprio arquivo mostra como gerar uma)

python manage.py migrate
python manage.py seed_governance   # dados fictícios de demonstração
python manage.py create_root       # superusuário de desenvolvimento; a senha é exibida uma única vez
python manage.py runserver
```

Acesse http://127.0.0.1:8000. No primeiro login o sistema pede o cadastro de um aplicativo
autenticador (Google Authenticator, Microsoft Authenticator, Aegis etc.).

`seed_governance` e `create_root` só funcionam com `DEBUG=True` e se recusam a rodar em produção.

## 🏭 Produção (Docker Compose + Caddy)

A pilha sobe PostgreSQL, a aplicação (Gunicorn) e o Caddy, que obtém o certificado TLS
automaticamente.

1. Crie o `.env` no servidor com, no mínimo:

   ```bash
   SECRET_KEY=<gere com: python -c "import secrets; print(secrets.token_urlsafe(50))">
   POSTGRES_PASSWORD=<senha forte>
   DOMAIN=gatekeeper.suaempresa.com.br
   ALLOWED_HOSTS=gatekeeper.suaempresa.com.br
   ADMIN_URL=um-caminho-nao-obvio/      # o admin não fica em /admin/
   TIME_ZONE=America/Sao_Paulo
   ```

2. Suba a pilha:

   ```bash
   docker compose up -d --build
   ```

   O serviço `migrate` roda antes da aplicação: verifica a configuração (`check --deploy`),
   aplica as migrações e só então libera o `web`. Se a configuração for insegura, a aplicação
   não sobe — veja o motivo com `docker compose logs migrate`.

3. Crie o primeiro administrador:

   ```bash
   docker compose run --rm web python manage.py createsuperuser
   ```

4. Configure o backup diário (veja [Backups](#-backups)).

## ⚙️ Variáveis de ambiente

| Variável | Padrão | Para que serve |
|---|---|---|
| `SECRET_KEY` | — (obrigatória) | Chave criptográfica do Django. |
| `DEBUG` | `False` | Nunca use `True` em produção. |
| `ALLOWED_HOSTS` | `127.0.0.1,localhost` | Domínios aceitos, separados por vírgula. |
| `DATABASE_URL` | SQLite local | Ex.: `postgres://usuario:senha@host:5432/banco`. |
| `CACHE_URL` | `dbcache://gatekeeper_cache` | Cache compartilhado entre processos (rate limit e MFA). Aceita `redis://`. Não use cache local em produção. |
| `TIME_ZONE` | `America/Bahia` | Fuso da trilha de auditoria (nome IANA). |
| `ADMIN_URL` | `admin/` | Caminho do Django Admin. Mude em produção. |
| `DOMAIN` | `localhost` | Domínio do certificado TLS (Caddy). |
| `TRUSTED_PROXY_COUNT` | `0` | Quantos proxies confiáveis existem na frente da aplicação (o compose usa `1`). Necessário para registrar o IP real nos logs. |
| `USE_X_FORWARDED_PROTO` | `False` | `True` quando um proxy faz o TLS. |
| `SESSION_COOKIE_AGE` | `28800` | Duração da sessão em segundos (8 h). |
| `SECURE_HSTS_SECONDS` | 1 ano em produção | Duração do HSTS. |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` / `SECURE_HSTS_PRELOAD` | `False` | Ative só se **todos** os subdomínios tiverem HTTPS. |
| `DJANGO_LOG_LEVEL` | `INFO` | Nível dos logs. |

## 👥 Perfis de acesso

Criados automaticamente pelas migrações:

| Grupo | Pode |
|---|---|
| **Auditor** | Consultar tudo e emitir relatórios. Não altera nada. |
| **Analista TI** | O mesmo do Auditor + iniciar offboarding e revogar itens do checklist. |
| **Gestor SecOps** | Tudo, inclusive marcar itens como "Não Aplicável". |

O MFA é exigido pela **permissão efetiva** do usuário, não pelo nome do grupo: se você criar
grupos novos ou der permissões diretamente a alguém, quem puder alterar dados terá MFA
obrigatório automaticamente.

## 🧩 Adaptando para a sua empresa

- **Sistemas e perfis de acesso:** cadastre pelo Django Admin os sistemas da sua empresa (VPN,
  e-mail, ERP, SaaS…) com a criticidade e os perfis de cada um. Os dados do `seed_governance`
  são apenas exemplos.
- **Estrutura organizacional:** departamentos, cargos e localidades também ficam no Admin.
- **Grupos e permissões:** ajuste pelo Admin. Ao criar uma tela nova, registre-a no teste que
  percorre todas as rotas (veja o [template de PR](.github/pull_request_template.md)).
- **Fuso horário:** `TIME_ZONE`.
- **Idioma:** a interface está em português do Brasil.
- **Visual:** o CSS é gerado pelo Tailwind a partir de `static/css/input.css`. Depois de alterar
  templates ou o CSS, rode `scripts/build_css.sh` (baixa o Tailwind com verificação de checksum;
  não precisa de Node).

## 💾 Backups

`scripts/backup_db.sh` gera um dump criptografado com [age](https://github.com/FiloSottile/age)
usando apenas a **chave pública** — o servidor não consegue ler os próprios backups.

```bash
export BACKUP_AGE_RECIPIENT=age1...   # sua chave pública
export PGHOST=... PGUSER=... PGDATABASE=...   # senha em ~/.pgpass (permissão 600)
scripts/backup_db.sh
```

Guarde a chave privada fora do servidor e **teste a restauração periodicamente**.

## 🧪 Testes e qualidade

```bash
python manage.py test apps.governance   # suíte completa
ruff check . && ruff format --check .
bandit -c pyproject.toml -r apps core
pip-audit -r requirements.txt
pre-commit install                      # hooks locais (lint, segredos, CSS atualizado)
```

## 📁 Estrutura

```text
├── apps/governance/    # Modelos, regras de negócio (services.py), views, admin e testes
├── core/               # Configurações do Django (settings.py) e rotas
├── templates/          # Telas (inclui as de login/MFA do allauth)
├── static/             # CSS (fonte em static/css/input.css) e JS
├── scripts/            # Build do CSS e backup criptografado
├── docs/               # Documentação e Diário de Desenvolvimento
├── docker-compose.yml  # Produção: PostgreSQL + migrate + web + Caddy
├── Dockerfile
└── Caddyfile           # Proxy TLS e cabeçalhos de segurança
```

## 📖 Documentação

Cada fase do projeto — inclusive cada falha de segurança encontrada e como foi corrigida — está
registrada no [Diário de Desenvolvimento](docs/README.md).

## 🤝 Contribuindo

Pull requests são bem-vindos. O [template de PR](.github/pull_request_template.md) traz o
checklist de segurança que toda mudança precisa cumprir.

## 📄 Licença

Distribuído sob a [Licença Apache 2.0](LICENSE). Você pode usar, modificar e distribuir,
inclusive comercialmente, mantendo os avisos de copyright e do arquivo [NOTICE](NOTICE).
O nome "GateKeeper-DBF" não é licenciado como marca.
