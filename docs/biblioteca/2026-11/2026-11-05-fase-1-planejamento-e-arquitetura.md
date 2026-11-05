# 🛡️ Diário de Bordo: 2026-11-05 - Fase 1: Planejamento, Arquitetura & Governança

* **Data:** 05 de Novembro de 2026
* **Projeto:** GateKeeper-DBF (Identity & Access Management / Concentrador de Acessos)
* **Autor / Responsável:** David B. F.
* **Fase:** Fase 1 — Concepção, Defesa Arquitetural & Estruturação de Governança

---

## 1. 🎯 Contexto e Justificativa do Negócio

A empresa identificou um gap crítico no ciclo de vida de identidades: no momento do desligamento de colaboradores (offboarding), não há visibilidade centralizada sobre quais sistemas, acessos, permissões e privilégios estavam concedidos àquele profissional. 

Da mesma forma, no momento da admissão (onboarding), os líderes e o time de TI não dispõem de uma matriz clara do que conceder para cada cargo e filial, gerando atrasos na operação ou concessão excessiva de privilégios.

---

## 2. 🔍 Fundamentação em Cibersegurança & Conformidade

* **MITRE ATT&CK:**
  * **Tática:** Initial Access & Persistence
  * **Técnica:** `T1078 - Valid Accounts` (Prevenção contra exploração de contas órfãs / ex-colaboradores com credenciais ativas).
* **CIS Controls v8:**
  * **Controle 5 (Account Management):** Requisito 5.5 — Estabelecer e executar processo formal e auditável de revogação de acessos imediatamente no desligamento.
* **LGPD (Lei Geral de Proteção de Dados - Lei 13.709/2018):**
  * **Art. 46:** Adoção de medidas de segurança, técnicas e administrativas aptas a proteger os dados pessoais de acessos não autorizados.

---

## 3. ⚙️ Decisão de Stack Tecnológica: Python + Django

Após análise comparativa de segurança (OWASP Top 10), optou-se pelo ecossistema **Python + Django** pelos seguintes fatores determinantes:

1. **Defesa Nativa em Profundidade:**
   * Proteção automática contra **Cross-Site Request Forgery (CSRF)** em formulários web.
   * ORM com parametrização estrita, eliminando vulnerabilidades de **SQL Injection**.
   * Escape padrão nos templates contra **Cross-Site Scripting (XSS)**.
2. **Mecanismo de Autenticação & Hashing Seguro:**
   * Algoritmo nativo PBKDF2 com SHA-256 para senhas.
   * Sistema granular de RBAC (Role-Based Access Control) nativo com Usuários, Grupos e Permissões.
3. **Painel de Auditoria & Administração Integrado:**
   * Painel seguro para cadastro e governança dos ativos e registros de concessão.

---

## 4. 🔒 Política de Privacidade & DevSecOps (.gitignore)

Para garantir que o repositório no GitHub possa ser compartilhado de forma profissional sem expor nenhum dado corporativo sensível, foi implementada a seguinte política:
* **Bloqueio de Dados de Produção:** Criação de diretórios locais como `docs/privado/`, planilhas (`*.xlsx`, `*.csv`) e bancos de dados locais (`*.sqlite3`) bloqueados no `.gitignore`.
* **Segurança de Credenciais:** Nenhuma chave de API, segredo de aplicação (`.env`) ou senha será commitada no versionador.

---

## 5. 📋 Próximas Ações Planejadas

1. Estruturação do modelo de levantamento de sistemas por setor para alinhamento com as lideranças.
2. Criação do ambiente virtual Python (`venv`) e arquivo de dependências seguras (`requirements.txt`).
3. Inicialização do projeto base Django (`gatekeeper_core`) com configurações de segurança ativadas.

