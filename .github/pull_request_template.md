## O que muda

<!-- Descreva a mudança e o motivo. Referencie a issue/chamado, se houver. -->

## Como testar

<!-- Passos para validar, comandos executados e resultado esperado. -->

---

## ✅ Checklist de segurança (negar por padrão)

Marque cada item ou explique por que não se aplica.

### Acesso e autorização
- [ ] Nova view tem `PermissionRequiredMixin` / `@permission_required` **e** foi registrada no dicionário `rotas_protegidas` do teste-catraca (`test_52_catraca_todas_rotas_governance_exigem_permissao`).
- [ ] Rota pública nova (com `@login_not_required`) é realmente necessária e não expõe dados.
- [ ] Ações que alteram dados usam POST com `{% csrf_token %}` e registram `request.user` como responsável.

### Regras de negócio e auditoria
- [ ] Novo status ou fluxo tem **todas** as transições declaradas em `TRANSICOES_PERMITIDAS` (inclusive a saída de estados de erro).
- [ ] Nenhum caminho novo apaga ou sobrescreve evidência de auditoria (modelos com `PROTECT` e `simple_history`).
- [ ] Novo log usa `logger.info("EVENTO", extra={"audit": {...}})` — nunca f-string com dado digitado pelo usuário.

### Front-end
- [ ] Nenhum `style="..."`, `onclick=` ou `<script>` inline (a CSP bloqueia). Estilos vão para `static/css/`, scripts para `static/js/`.
- [ ] Nenhum recurso carregado de CDN externo.
- [ ] Nenhum `|safe`, `mark_safe` ou `{% autoescape off %}` com dado de usuário.

### Dependências, build e deploy
- [ ] Nova dependência: revisei **o que ela habilita por padrão** (URLs, telas públicas, configurações permissivas) e atualizei `requirements.txt` com hashes (`pip-compile --generate-hashes`).
- [ ] Novo arquivo/pasta necessário na imagem foi liberado explicitamente no `.dockerignore` (allowlist); arquivos sensíveis gerados estão no `.gitignore`.
- [ ] Nova variável de ambiente sensível é obrigatória no compose (`${VAR:?mensagem}`), sem valor padrão.
- [ ] Nenhum segredo, dado real de colaborador, dump de banco ou planilha no diff.

### Testes
- [ ] Cada brecha corrigida ou regra de segurança nova tem um teste de regressão.
- [ ] `ruff check`, `ruff format --check`, `bandit`, `pip-audit` e `python manage.py test` passam localmente.
