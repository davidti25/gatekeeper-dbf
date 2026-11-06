# Política de Segurança

O GateKeeper-DBF controla quem tem acesso a quê numa empresa. Uma falha aqui pode significar
um ex-colaborador com acesso ativo ou uma trilha de auditoria adulterada, por isso relatos de
vulnerabilidade são muito bem-vindos e tratados com prioridade.

## Versões suportadas

| Versão | Recebe correções de segurança |
|---|---|
| Branch `main` (última versão) | ✅ |
| Commits ou forks anteriores | ❌ — atualize para a `main` |

## Como reportar uma vulnerabilidade

**Não abra uma issue pública.** Uma issue expõe a falha a todos antes que exista correção.

Use o canal privado do GitHub:

1. Acesse a aba **Security** deste repositório.
2. Clique em **Report a vulnerability**.
3. Descreva:
   - o que é afetado (tela, rota, comando ou arquivo);
   - os passos para reproduzir, com o perfil de usuário usado (Auditor, Analista TI, Gestor SecOps ou staff);
   - o impacto que você conseguiu demonstrar;
   - se possível, uma sugestão de correção.

## O que esperar

- Confirmação de recebimento em até **7 dias**.
- Avaliação de severidade e plano de correção em seguida.
- A correção é publicada com um teste de regressão e registrada no
  [Diário de Desenvolvimento](docs/README.md). Se você quiser, seu nome é creditado.

Pedimos que a falha só seja divulgada publicamente depois de corrigida, ou após 90 dias do
relato, o que acontecer primeiro.

## Escopo

**Dentro do escopo:** o código deste repositório, incluindo `docker-compose.yml`, `Caddyfile`,
`Dockerfile`, os scripts em `scripts/` e as configurações padrão.

**Fora do escopo:**

- instalações de terceiros com configuração alterada (ex.: `DEBUG=True` em produção);
- vulnerabilidades em dependências já corrigidas em versões que o projeto ainda não adotou
  (abra uma issue normal ou um PR atualizando a dependência);
- ataques que exigem acesso físico ou de administrador ao servidor;
- negação de serviço por volume.

## Para quem instala o GateKeeper-DBF

Antes de colocar em produção, rode `python manage.py check --deploy`: ele precisa terminar sem
erros. O serviço `migrate` do `docker-compose.yml` já faz essa verificação e impede a subida da
aplicação se a configuração for insegura. Veja também a seção "Produção" do [README](README.md).
