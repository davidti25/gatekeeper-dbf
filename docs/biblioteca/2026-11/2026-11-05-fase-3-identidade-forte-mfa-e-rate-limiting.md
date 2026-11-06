# 🛡️ Diário de Bordo: 2026-11-05 - Fase 3: Identidade Forte — MFA & Rate Limiting

* **Data:** 05 de Novembro de 2026
* **Projeto:** GateKeeper-DBF (Central de Governança de Acessos & Offboarding Seguro)
* **Autor / Responsável:** David B. F.
* **Origem:** Implementação da Fase 3 do Plano de Ação de Segurança & Qualidade
* **Fase:** Fase 3 — Identidade Forte (MFA, Rate Limiting & Proteção contra Brute Force)
* **Status:** ✅ Concluída

---

## 1. 🔍 Resumo Executivo & Severidade

* **Severidade Prévia:** `[ALTA]` (Risco de sequestro de credenciais administrativas, enumeração de senhas e falta de segundo fator de autenticação em um sistema crítico de IAM).
* **Mapeamento Normativo:**
  * **CIS Controls v8:** Salvaguarda 6.5 (*Require MFA for Externally-Exposed Applications & Administrative Access*).
  * **NIST SP 800-63B:** AAL2 (*Authenticator Assurance Level 2* — Exigência de fator independente de posse TOTP).
  * **LGPD Art. 46:** Adoção de medidas de segurança aptas a proteger os dados de acessos não autorizados.

* **O que foi implementado:**
  A plataforma agora conta com um ecossistema completo de **Identidade Forte** baseado em `django-allauth[mfa]`. Foram implementados: suporte nativo a múltiplos fatores de autenticação (aplicativos autenticadores baseados em tempo — TOTP via RFC 6238 e códigos estáticos de recuperação de emergência); proteção ativa contra ataques de força bruta e credential stuffing através de **Rate Limiting** granular configurado na camada de aplicação; blindagem do login nativo do Django Admin (`/admin/login/`) redirecionando estritamente para o fluxo seguro; e templates 100% integrados à identidade visual Dark SOC com suporte à Content Security Policy estrita.

---

## 2. 🎯 Mapeamento MITRE ATT&CK

| Tática | Técnica | ID | Mitigação no GateKeeper-DBF |
| :--- | :--- | :--- | :--- |
| **Credential Access** | Brute Force: Password Guessing | `T1110.001` | `ACCOUNT_RATE_LIMITS = {'login_failed': '5/5m'}` bloqueia tentativas repetidas por IP/chave antes que possam sobrecarregar a infraestrutura ou comprometer contas. |
| **Credential Access** | Brute Force: Password Spraying | `T1110.003` | Limitação de requisições de login por janela de tempo e logs de auditoria SOC em nível `WARNING`. |
| **Defense Evasion** | Valid Accounts | `T1078` | Exigência de MFA (TOTP). O comprometimento da senha não é suficiente para obter acesso à sessão de operador ou administrador. |
| **Persistence** | Modify Authentication Process | `T1556` | Unificação do fluxo de login administrativo via `secure_admin_login(admin.site.login)`, impedindo desvios do fluxo MFA pelo Django Admin. |

---

## 3. 🛠️ Detalhamento das Implementações Técnicas

### 3.1 Integração com `django-allauth[mfa]` & Compilação Criptográfica
* Adicionado `django-allauth[mfa]` ao [`requirements.in`](requirements.in).
* Recompilado [`requirements.txt`](requirements.txt) utilizando `pip-compile --generate-hashes`, fixando `django-allauth==65.21.1` e suas dependências (`qrcode`, etc.) com hashes criptográficos SHA-256.
* Integrados os apps em [`core/settings.py`](core/settings.py):
  * `'allauth'`
  * `'allauth.account'`
  * `'allauth.mfa'`
* Configurados os backends e middlewares essenciais:
  * `AUTHENTICATION_BACKENDS`: adicionado `allauth.account.auth_backends.AuthenticationBackend`.
  * `MIDDLEWARE`: adicionado `allauth.account.middleware.AccountMiddleware`.
* Executadas as migrações de banco de dados (`account` 0001-0009 e `mfa` 0001-0003), criando as tabelas de gerenciamento de e-mails de auditoria (`account_emailaddress`) e autenticadores criptográficos (`mfa_authenticator`).

### 3.2 Política Estrita de Rate Limiting (Anti-Brute Force)
* Configurado em [`core/settings.py`](core/settings.py):
  ```python
  ACCOUNT_RATE_LIMITS = {
      "login_failed": "5/5m",  # Máximo de 5 falhas a cada 5 minutos por IP/usuário
  }
  ```
* Quando a taxa é ultrapassada, o allauth intercepta a tentativa **antes** de executar hash de senha no banco de dados, protegendo contra exaustão de CPU (DoS em PBKDF2) e apresentando alerta ao usuário: *"Muitas tentativas de login falharam. Tente novamente mais tarde."*

### 3.3 Blindagem do Django Admin (`secure_admin_login`)
* **Problema:** A interface do Django Admin tradicional possui seu próprio formulário em `/admin/login/`, que contornaria as regras de MFA e proteções de login único configuradas no allauth.
* **Solução:** Em [`core/urls.py`](core/urls.py), o ponto de entrada de login do admin foi decorado com `secure_admin_login`:
  ```python
  from allauth.account.decorators import secure_admin_login

  admin.site.login = secure_admin_login(admin.site.login)
  ```
* Usuários não autenticados que tentarem acessar `/admin/login/` recebem `HTTP 302` redirecionando para `/login/?next=/admin/login/`, garantindo que todos os acessos administrativos passem pelo fluxo unificado e protegido por MFA.

### 3.4 Configurações de MFA & Identidade
* `ACCOUNT_LOGIN_METHODS = {'email', 'username'}`: Permite autenticação por e-mail corporativo ou nome de usuário.
* `ACCOUNT_SIGNUP_FIELDS = ['username', 'email']`: Garante que novos usuários cadastrados tenham ambos os campos preenchidos.
* `MFA_SUPPORTED_TYPES = ['totp', 'recovery_codes']`: Habilita aplicativos autenticadores (Google Authenticator, Microsoft Authenticator, Bitwarden, Aegis) e códigos de backup.
* `MFA_TOTP_ISSUER = 'GateKeeper-DBF'`: Identificador claro nos apps de token dos operadores.

### 3.5 Interface do Usuário Dark SOC & Conformidade com CSP
* Customizados os layouts de template em `templates/allauth/layouts/`:
  * `entrance.html`: Layout centrado, moderno, dark slate, com badges de conformidade (CIS v8, NIST SP 800-63B).
  * `manage.html`: Layout integrado com navegação superior para gestão de tokens e credenciais.
* Customizado [`templates/account/login.html`](templates/account/login.html):
  * Formulário estilizado com foco nos padrões de SOC, utilizando ícones Lucide locais e tipografia Inter/JetBrains Mono.
  * Compatível com campos `login` e `password` do allauth, sem scripts inline ou violações de CSP.
* Adicionado botão de atalho direto para gestão de MFA no cabeçalho do [`templates/base.html`](templates/base.html), permitindo que qualquer operador autenticado ative e gerencie seus fatores de autenticação.

---

## 4. 🧪 Validação Automatizada de Testes Unitários

Foi criada a suíte `Phase3StrongIdentityAndMFATests` em [`apps/governance/tests.py`](apps/governance/tests.py), totalizando **20 testes unitários automatizados** na aplicação:

1. `test_30_admin_login_protegido_secure_admin_login`: Garante que o `/admin/login/` não abre tela de senha legada e redireciona 302 para `/login/?next=%2Fadmin%2Flogin%2F`.
2. `test_31_mfa_endpoints_acessiveis_e_protegidos`: Valida que o endpoint `/accounts/2fa/` exige login (redireciona unauthenticated com 302) e responde `200 OK` para operadores autenticados exibindo opções de ativação de TOTP e códigos de recuperação.
3. `test_32_rate_limit_tentativas_excessivas_de_login`: Simula ataques consecutivos de dicionário/senha incorreta; após o 5º erro, o sistema ativa o limitador de taxa e bloqueia a 6ª tentativa.
4. `test_33_mfa_models_migrados_e_disponiveis`: Valida a integridade relacional dos modelos de e-mail e autenticadores MFA no banco de dados.

### Resultado da Execução:
```text
Found 20 test(s).
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
....................
----------------------------------------------------------------------
Ran 20 tests in 18.142s

OK
Destroying test database for alias 'default'...
```

---

## 5. 💡 Dica de Bootcamp & Boas Práticas de Engenharia de Detecção

> [!TIP]
> **Por que o Rate Limiting no nível da Aplicação complementa (e não substitui) o Firewall de Rede (MikroTik/WAF)?**
> * **Defesa em Profundidade:** No roteador de borda (MikroTik RouterOS ou pfSense), podemos criar regras de firewall RAW ou filter com `connection-limit` ou `dst-limit` para barrar flooding de pacotes SYN (ataques L4).
> * **No entanto**, ataques de força bruta lentos (*Slow & Low* ou *Password Spraying*) usam conexões legítimas HTTP e proxies rotativos. O firewall de borda não sabe se uma credencial é válida ou inválida.
> * É o **Rate Limiting da aplicação (L7)** que correlaciona o `AUTH_LOGIN_FAILED` por conta ou por bloco IP, impedindo que credenciais sejam quebradas sem saturar a rede. No SIEM (Wazuh/Elastic), a regra correlaciona múltiplos logs `AUTH_LOGIN_FAILED` para gerar o alerta de incidente (MITRE T1110) e despachar bloqueio automatizado na `address-list` do firewall via webhook ou API.
