# 🛡️ Diário de Bordo: 2026-11-05 - Fase 2: Plataforma & Hardening de Configuração

* **Data:** 05 de Novembro de 2026
* **Projeto:** GateKeeper-DBF (Central de Governança de Acessos & Offboarding Seguro)
* **Autor / Responsável:** David B. F.
* **Origem:** Implementação da Fase 2 do Plano de Ação de Segurança & Qualidade
* **Fase:** Fase 2 — Plataforma & Hardening de Configuração (OWASP / CIS Controls v8 / DevSecOps)
* **Status:** ✅ Concluída

---

## 1. 🎯 Objetivos Executados & Implementações Técnicas

### 2.1 Migração para Django 5.2 LTS & Remoção de Monkeypatch
* **Problema:** O Django 5.1 atingiu fim de suporte (EOL) em dezembro de 2025, deixando de receber correções de segurança contra vulnerabilidades críticas. Além disso, existia um *monkeypatch* em `settings.py` para contornar a incompatibilidade do Python 3.14 com o contexto de templates.
* **Solução Implementada:**
  * Atualizado o framework para **Django 5.2.19 (LTS)** com suporte oficial estendido até abril de 2028.
  * Removido integralmente o *monkeypatch* `_py314_context_copy` de [`core/settings.py`](core/settings.py), restabelecendo o comportamento limpo e nativo do framework.

### 2.2 Dependências com Hash Criptográfico & Dependabot (`pip-tools`)
* **Problema:** O uso de `requirements.txt` sem hashes criptográficos abria vetor para ataques de cadeia de suprimentos (*Supply Chain Poisoning* / *Dependency Confusion*), onde um pacote adulterado poderia ser injetado durante o build.
* **Solução Implementada:**
  * Criado [`requirements.in`](requirements.in) contendo as dependências de topo declarativas.
  * Utilizado `pip-compile --generate-hashes` para gerar [`requirements.txt`](requirements.txt) com validação estrita de integridade via **SHA-256** para cada pacote e subdependência.
  * Configurado o [`.github/dependabot.yml`](.github/dependabot.yml) para monitoramento semanal automatizado de vulnerabilidades e atualizações de pacotes.

### 2.3 Front-end Local, Sem CDNs e com Content Security Policy (CSP) Rígida
* **Problema:** A aplicação utilizava `cdn.tailwindcss.com` (versão Play, não recomendada para produção), `unpkg.com` e fontes do Google. Além do risco de Supply Chain via CDNs comprometidos, o carregamento de fontes do Google enviava os endereços IP dos operadores para servidores externos (risco de conformidade LGPD). A presença de scripts inline (`<script>` e `onclick`) impedia a ativação de uma CSP rígida.
* **Solução Implementada:**
  * **Tailwind CSS Compilado Localmente:** Configurado [`tailwind.config.js`](tailwind.config.js) e compilado o CSS em [`static/css/tailwind.min.css`](static/css/tailwind.min.css) (apenas 31KB, contendo estritamente as classes utilizadas nos templates).
  * **Tipografia Local (Inter & JetBrains Mono):** Baixados os arquivos WOFF2 das fontes Inter e JetBrains Mono para [`static/fonts/`](static/fonts/) com mapeamento em [`static/fonts/fonts.css`](static/fonts/fonts.css), eliminando qualquer vazamento de IP.
  * **Ícones Lucide Locais:** Servidos diretamente de [`static/vendor/lucide.min.js`](static/vendor/lucide.min.js).
  * **Eliminação de Scripts Inline:** Movidos os inicializadores de ícones e botões de ação para [`static/js/app.js`](static/js/app.js) e [`static/css/print.css`](static/css/print.css).
  * **WhiteNoise com Manifest & Compressão:** Ativado `whitenoise.middleware.WhiteNoiseMiddleware` com `CompressedManifestStaticFilesStorage` em `STORAGES`, garantindo hash de cache busting e compressão gzip/brotli.
  * **Content Security Policy Estrita (`django-csp` 4.x):** Configurado `CONTENT_SECURITY_POLICY` bloqueando origens externas e **proibindo `'unsafe-inline'`**:
    ```python
    CONTENT_SECURITY_POLICY = {
        "DIRECTIVES": {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'", "data:"],
            "font-src": ["'self'"],
            "connect-src": ["'self'"],
            "frame-ancestors": ["'none'"],
            "form-action": ["'self'"],
        }
    }
    ```

### 2.4 Blindagem de Configuração de Produção (`check --deploy`) & Auditoria SOC
* **Configuração de Cookies & Sessão:**
  * `SESSION_COOKIE_AGE = 28800` (8 horas, correspondente a uma jornada de trabalho).
  * `SESSION_EXPIRE_AT_BROWSER_CLOSE = True`.
  * `SESSION_COOKIE_HTTPONLY = True` e `CSRF_COOKIE_HTTPONLY = True`.
  * `SESSION_COOKIE_SECURE = True` e `CSRF_COOKIE_SECURE = True` em ambiente de produção.
* **HSTS & HTTPS:**
  * `SECURE_HSTS_SECONDS = 31536000` (1 ano).
  * `SECURE_HSTS_INCLUDE_SUBDOMAINS = True` e `SECURE_HSTS_PRELOAD = True`.
  * `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')`.
* **Ofuscação de Rota Administrativa:**
  * Parâmetro `ADMIN_URL = env('ADMIN_URL', default='admin/')` em [`core/urls.py`](core/urls.py).
* **Limpeza de Parâmetros Obsoletos:**
  * Removido `SECURE_BROWSER_XSS_FILTER` (obsoleto e ineficaz em navegadores modernos).
  * Removida a injeção manual de `testserver` em `ALLOWED_HOSTS`.
* **Trilha de Auditoria Estruturada (SOC / SIEM):**
  * Criado o logger dedicado `'gatekeeper.audit'` no dicionário `LOGGING`.
  * Implementado [`apps/governance/signals.py`](apps/governance/signals.py) capturando eventos:
    * `AUTH_LOGIN_SUCCESS`: Login auditado com usuário e IP.
    * `AUTH_LOGIN_FAILED`: Tentativas frustradas de login (alerta para brute force — **MITRE ATT&CK T1110**).
    * `AUTH_LOGOUT`: Encerramento formal de sessão.
    * `OFFBOARDING_PROCESS_INITIATED` e `OFFBOARDING_ITEM_REVOKED`: Ações críticas de encerramento de acessos.
* **Validação de Deploy:**
  * `python manage.py check --deploy` executado em modo de produção resultando em **zero avisos ou erros** (`System check identified no issues (0 silenced)`).

### 2.5 Ajustes Rápidos de Permissão & Links
* Aplicado `chmod -R go-w` nos diretórios do projeto (`apps`, `core`, `docs`, `templates`, `static`), eliminando permissões mundiais de escrita (`777` -> `755`).
* Corrigidos links de documentação em [`README.md`](README.md) e [`docs/README.md`](docs/README.md) para caminhos relativos de repositório.

---

## 2. 🧪 Validação Automatizada da Suíte de Testes

Criada a classe `Phase2PlatformAndHardeningTests` em [`apps/governance/tests.py`](apps/governance/tests.py), elevando a suíte para **16 testes automatizados**:

* `test_20_csp_headers_sem_unsafe_inline`: Valida presença de `Content-Security-Policy` sem `'unsafe-inline'` e com `default-src 'self'`.
* `test_21_recursos_estaticos_locais_sem_cdns_externos`: Assegura ausência de CDNs externos (`cdn.tailwindcss.com`, `unpkg.com`, `fonts.googleapis.com`) e entrega 100% local via WhiteNoise.
* `test_22_sessao_e_hardening_cookies`: Confirma flags `HttpOnly`, `SESSION_COOKIE_AGE=28800` e `DENY` para `X-Frame-Options`.
* `test_23_trilha_auditoria_soc_sinais`: Valida emissão de logs estruturados em sinais de login e logout.

**Resultado da execução dos testes:**
```text
Found 16 test(s).
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
................
----------------------------------------------------------------------
Ran 16 tests in 15.418s

OK (100% aprovados)
Destroying test database for alias 'default'...
```

---

## 3. 🛡️ Mapeamento de Conformidade e Frameworks

* **OWASP Top 10 (A05:2021 - Security Misconfiguration):**
  * Eliminação de Play CDN, ativação de CSP rígida e validação estrita com `check --deploy`.
* **OWASP Top 10 (A03:2021 - Injection / XSS):**
  * Neutralização definitiva de XSS com Content Security Policy sem `unsafe-inline`.
* **CIS Controls v8 — Controle 5 (Account Management) & 6 (Access Control Management):**
  * Sessão limitada a 8 horas com encerramento no fechamento do navegador.
* **LGPD — Art. 46:**
  * Fontes e scripts servidos localmente, impedindo o tráfego de IPs e metadados para servidores de terceiros.
* **MITRE ATT&CK — T1110 (Brute Force) & T1078 (Valid Accounts):**
  * Captura de logs em tempo real de falhas de autenticação (`AUTH_LOGIN_FAILED`) e trilha de auditoria de revogações.

---

## 4. 📋 Próximo Passo

Avançar para a **Fase 3 — Identidade Forte**:
* **3.1:** `django-allauth` com módulo MFA (TOTP, WebAuthn/Passkeys, códigos de recuperação), proteção contra ataques de força bruta com `ACCOUNT_RATE_LIMITS` e autenticação reforçada no Django Admin.
