# GateKeeper-DBF 🛡️
> **Central de Governança de Acessos, Matriz RBAC & Gestão de Offboarding Seguro**  
> *Desenvolvido e Mantido por David B. F. • Engenharia de Cibersegurança & SecOps*

---

## 🎯 Sobre o Projeto

O **GateKeeper-DBF** é uma solução de **IAM (Identity & Access Management)** e **Governança de Identidades** concebida para sanar uma das maiores vulnerabilidades de segurança corporativa: a **falta de visibilidade e controle sobre os acessos de colaboradores desligados (offboarding)** e a desordem na concessão de privilégios para novos contratados (onboarding).

A aplicação atua como a **Fonte Única da Verdade (Single Source of Truth)** para a equipe de TI e Segurança da Informação, mapeando colaboradores, filiais/localidades, cargos e os sistemas/ativos concedidos.

---

## 🚨 O Problema de Segurança Resolvido

1. **Eliminação de Contas Órfãs (*Orphan Accounts*):**
   * Previne a persistência de credenciais ativas de ex-colaboradores em VPNs, e-mails, roteadores MikroTik, bancos de dados e sistemas SaaS.
   * **Mapeamento MITRE ATT&CK:** Tática **Initial Access / Persistence** — Técnica **[T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)**.
2. **Mitigação do *Privilege Creep*:**
   * Evita o acúmulo descontrolado de privilégios conforme o colaborador transita entre setores.
3. **Conformidade Normativa (Compliance):**
   * **CIS Controls v8:** Controle 5 (Account Management) - Requisito 5.5 (Revogação formal no desligamento).
   * **LGPD (Lei 13.709/2018):** Art. 46 (Proteção contra acessos não autorizados e vazamentos).
   * **ISO 27001:** Controle A.9.2.6 (Remoção ou ajuste de direitos de acesso).

---

## 🛠️ Stack Tecnológica & Segurança

* **Linguagem:** Python 3.12+
* **Framework:** Django (Full-Stack Seguro)
  * Proteção nativa contra **OWASP Top 10** (CSRF, SQL Injection, XSS, Clickjacking).
  * Hashing de senhas seguro (PBKDF2 com SHA-256).
  * Sistema nativo de **RBAC (Role-Based Access Control)** com grupos e permissões.
* **Banco de Dados:** SQLite (Desenvolvimento) / PostgreSQL (Produção).
* **Front-end:** Django Templates com design responsivo e seguro.

---

## 📁 Estrutura do Repositório

```text
GateKeeper-DBF/
├── docs/
│   ├── biblioteca/         # Diário de bordo das fases (YYYY-MM-DD-*)
│   │   └── 2026-11/
│   ├── modelos/            # Templates e formulários de levantamento
│   ├── privado/            # (Local / Git-ignored) Dados sensíveis e LGPD
│   └── README.md           # Índice central da documentação
├── .gitignore              # Blindagem DevSecOps contra vazamento de dados
└── README.md               # Apresentação principal do projeto
```

---

## 🔒 Política de Privacidade & DevSecOps (LGPD)

Este repositório segue rígidas práticas de **DevSecOps**:
* **Nenhum dado real de colaborador, senha ou credencial de produção é commitado no Git.**
* A pasta `docs/privado/`, planilhas de levantamento (`*.xlsx`, `*.csv`) e variáveis de ambiente (`.env`) estão permanentemente blindadas no `.gitignore`.

---

## 📖 Diário de Desenvolvimento

A evolução diária deste projeto é documentada detalhadamente na nossa [Biblioteca de Documentação](file:///home/davidbf/dev/GateKeeper-DBF/docs/README.md).

