# 📋 Modelo de Levantamento de Sistemas & Acessos por Setor

> **Nota de Confidencialidade:** Este é um modelo de questionário técnico. Quando preenchido com dados reais da empresa, o documento resultante deve ser salvo exclusivamente na pasta local `docs/privado/` (bloqueada pelo `.gitignore`) para conformidade com a LGPD.

---

## 🏢 Identificação do Setor
* **Nome do Setor / Departamento:** [Ex: Financeiro, Logística, Comercial, Recursos Humanos]
* **Gestor / Líder Responsável:** [Nome do Líder]
* **Localidades / Filiais:** [Ex: Matriz, Filial SP, Filial RJ, Home Office]
* **Data do Levantamento:** `AAAA-MM-DD`

---

## 👥 Cargos e Funções do Setor
| Cargo / Função | Quantidade Atual de Colaboradores | Descrição Básica das Atividades |
| :--- | :---: | :--- |
| Ex: Assistente Financeiro | 3 | Contas a pagar, emissão de boletos, conciliação bancária |
| Ex: Coordenador de Contas | 1 | Aprovação de pagamentos, relatórios fiscais |

---

## 💻 Inventário de Sistemas e Ferramentas Utilizadas
Para cada sistema que os colaboradores desse setor utilizam, preencha as informações abaixo:

### Sistema 1: [Nome do Sistema / Ex: ERP Totvs, Omie, ContaAzul, etc.]
* **Tipo do Sistema:** [ ] Web / SaaS (Nuvem)  [ ] Instalado Localmente  [ ] Pasta Compartilhada / Rede
* **Finalidade no Setor:** [Ex: Faturamento e Emissão de Notas Fiscais]
* **Cargos que Utilizam:** [Ex: Assistente e Coordenador]
* **Perfis / Níveis de Permissão Existentes:**
  * Perfil 1: [Ex: Apenas Leitura / Consulta]
  * Perfil 2: [Ex: Lançamento e Edição]
  * Perfil 3: [Ex: Administrador / Aprovação Final]
* **Forma de Login / Autenticação:**
  * [ ] Login Individual com E-mail Corporativo
  * [ ] Integrado ao Active Directory (AD / Windows)
  * [ ] Conta Compartilhada / Senha Genérica *(⚠️ Ponto de Atenção de Segurança)*
* **Responsável Atual pela Criação/Exclusão do Acesso:**
  * [ ] TI Interna
  * [ ] O próprio Líder do Setor
  * [ ] Suporte / Fornecedor Externo do Software

---

## 🚨 Análise de Risco no Desligamento (Offboarding)
1. **Se um colaborador deste setor for desligado agora, esse sistema pode ser acessado de fora da empresa (pela internet/celular)?**
   * [ ] Sim, qualquer lugar via navegador.
   * [ ] Somente se estiver conectado na VPN da empresa.
   * [ ] Não, apenas fisicamente na rede da empresa.

2. **Quais dados sensíveis estão armazenados nesse sistema?**
   * [ ] Dados Pessoais (LGPD) - CPF, endereço, dados de clientes/funcionários.
   * [ ] Dados Financeiros / Bancários.
   * [ ] Dados Estratégicos / Contratos / Preços.

3. **Existe conta de Administrador disponível para a TI assumir a gestão centralizada desse software?**
   * [ ] Sim, a TI já possui ou receberá as credenciais master.
   * [ ] Não, precisa ser solicitado suporte com o fornecedor.

