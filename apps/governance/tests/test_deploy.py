"""
Testes do módulo de Governança & IAM - GateKeeper-DBF.
"""

import re
from pathlib import Path
from unittest import mock

from allauth.mfa.models import Authenticator
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.db import OperationalError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.governance.models import (
    Cargo,
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    Localidade,
    ProcessoOffboarding,
    Sistema,
    VinculoAcesso,
)
from apps.governance.tests.base import (
    setup_fase10_fixtures,
)

User = get_user_model()


class DeployPlataformaHardeningTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="soc.auditor", email="soc@empresa.com.br", password="ComplexPassword123!"
        )
        grupo_auditor = Group.objects.get(name="Auditor")
        self.user.groups.add(grupo_auditor)

    def test_20_csp_headers_sem_unsafe_inline(self):
        """2.3: Cabeçalho Content-Security-Policy presente e bloqueando inline scripts externos."""
        resp = self.client.get(reverse("login"))
        self.assertEqual(resp.status_code, 200)

        self.assertIn("Content-Security-Policy", resp.headers)
        csp = resp.headers["Content-Security-Policy"]

        # default-src 'self'
        self.assertIn("default-src 'self'", csp)
        # script-src 'self' sem 'unsafe-inline'
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("'unsafe-inline'", csp)
        # frame-ancestors 'none' (anti-clickjacking)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_21_recursos_estaticos_locais_sem_cdns_externos(self):
        """2.3: Front-end servido 100% de static/ sem dependência de CDNs ou envio de dados/IP para terceiros (LGPD)."""
        self.client.force_login(self.user)
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.status_code, 200)

        # Não deve haver conexões externas para Google Fonts, CDN Tailwind ou Unpkg
        self.assertNotContains(resp, "cdn.tailwindcss.com")
        self.assertNotContains(resp, "unpkg.com")
        self.assertNotContains(resp, "fonts.googleapis.com")
        self.assertNotContains(resp, "fonts.gstatic.com")

        # Deve conter as rotas locais compiladas e servidas pelo WhiteNoise (com ou sem hash)
        content = resp.content.decode()
        self.assertIn("/static/fonts/fonts.", content)
        self.assertIn("/static/css/tailwind.min.", content)
        self.assertIn("/static/vendor/lucide.min.", content)
        self.assertIn("/static/js/app.", content)


class DeployInfraestruturaEComposeTests(TestCase):
    def setUp(self):
        self.base_dir = Path(settings.BASE_DIR)

    def test_81_docker_compose_fail_closed_sem_senhas_default(self):
        """8.1: docker-compose.yml exige variáveis obrigatórias :? e não possui senhas padrão conhecidas."""
        compose_path = self.base_dir / "docker-compose.yml"
        self.assertTrue(compose_path.exists(), "docker-compose.yml não encontrado na raiz.")

        conteudo = compose_path.read_text(encoding="utf-8")

        # Exige sintaxe fail-closed :?
        self.assertIn("${SECRET_KEY:?", conteudo)
        self.assertIn("${POSTGRES_PASSWORD:?", conteudo)

        # Proíbe senhas padrão antigas no compose
        self.assertNotIn("gatekeeper_secure_password_2026", conteudo)
        self.assertNotIn("generate-a-secure-secret-key-for-production-min-50-chars", conteudo)

    def test_82_proxy_reverso_caddy_e_x_forwarded_proto(self):
        """8.2: Caddyfile configurado para terminação TLS e USE_X_FORWARDED_PROTO condicional."""
        caddyfile_path = self.base_dir / "Caddyfile"
        self.assertTrue(caddyfile_path.exists(), "Caddyfile deve existir na raiz do projeto.")

        caddy_content = caddyfile_path.read_text(encoding="utf-8")
        self.assertIn("reverse_proxy web:8000", caddy_content)
        self.assertIn("Strict-Transport-Security", caddy_content)

        # Valida que o compose isolou o serviço web (expose 8000, sem ports exposta no host)
        compose_content = (self.base_dir / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("caddy:", compose_content)
        self.assertIn('expose:\n      - "8000"', compose_content)

        # Valida configuração do Django no core.settings
        from django.conf import settings

        # Por padrão (sem env), USE_X_FORWARDED_PROTO é False e SECURE_PROXY_SSL_HEADER é None
        self.assertFalse(getattr(settings, "USE_X_FORWARDED_PROTO", False))
        self.assertIsNone(getattr(settings, "SECURE_PROXY_SSL_HEADER", None))

    def test_83_dockerignore_allowlist_e_gitignore_backups(self):
        """8.3: .dockerignore adota allowlist (negação universal *) e .gitignore barra backups/dumps."""
        dockerignore_path = self.base_dir / ".dockerignore"
        self.assertTrue(dockerignore_path.exists())

        di_lines = [
            line.strip()
            for line in dockerignore_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertEqual(di_lines[0], "*", ".dockerignore deve iniciar com negação universal '*'.")
        self.assertTrue(any(line.startswith("!apps/") for line in di_lines))
        self.assertTrue(any(line.startswith("!core/") for line in di_lines))

        # .gitignore
        gitignore_path = self.base_dir / ".gitignore"
        gi_content = gitignore_path.read_text(encoding="utf-8")
        self.assertIn("backups/", gi_content)
        self.assertIn("*.sql.gz", gi_content)
        self.assertIn("*.dump", gi_content)
        self.assertIn("*.age", gi_content)

    def test_84_script_backup_usa_age_chave_publica(self):
        """8.4: backup_db.sh valida chave pública age, opera em pipe e não expõe senhas na linha de comando."""
        script_path = self.base_dir / "scripts" / "backup_db.sh"
        self.assertTrue(script_path.exists())

        script_content = script_path.read_text(encoding="utf-8")
        # Validação da variável obrigatória da chave age
        self.assertIn("BACKUP_AGE_RECIPIENT:?", script_content)
        # Uso do age com chave pública
        self.assertIn("age -r", script_content)
        # Nenhuma senha exposta na CLI do openssl
        self.assertNotIn("-pass pass:", script_content)
        self.assertNotIn("openssl enc", script_content)

    def test_85_hsts_conservador_por_padrao(self):
        """8.5: HSTS preload e subdomínios desativados por padrão para evitar quebra de domínios corporativos."""
        from django.conf import settings

        self.assertFalse(settings.SECURE_HSTS_PRELOAD)
        self.assertFalse(settings.SECURE_HSTS_INCLUDE_SUBDOMAINS)

    def test_86_env_example_e_dependabot_actions(self):
        """8.6: .env.example deixa desativações de cookies comentadas e dependabot monitora github-actions."""
        env_example_path = self.base_dir / ".env.example"
        env_content = env_example_path.read_text(encoding="utf-8")

        # As linhas perigosas devem estar devidamente comentadas (#)
        self.assertIn("# SESSION_COOKIE_SECURE=False", env_content)
        self.assertIn("# CSRF_COOKIE_SECURE=False", env_content)
        self.assertIn("# SECURE_SSL_REDIRECT=False", env_content)

        # Dependabot
        dependabot_path = self.base_dir / ".github" / "dependabot.yml"
        dependabot_content = dependabot_path.read_text(encoding="utf-8")
        self.assertIn("github-actions", dependabot_content)

        # GitHub Actions CI com fixação por SHA
        ci_path = self.base_dir / ".github" / "workflows" / "ci.yml"
        ci_content = ci_path.read_text(encoding="utf-8")
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", ci_content)
        self.assertIn("actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38", ci_content)


class DeployHealthCheckEChecklistTests(TestCase):
    def setUp(self):
        self.base_dir = Path(settings.BASE_DIR)

        self.user_auditor = User.objects.create_user(
            username="auditor.fase9", email="auditor.fase9@empresa.com.br", password="ComplexPassword123!"
        )
        self.user_auditor.groups.add(Group.objects.get(name="Auditor"))
        responsavel = User.objects.create_user(
            username="analista.fase9", email="analista.fase9@empresa.com.br", password="ComplexPassword123!"
        )

        depto = Departamento.objects.create(nome="Infraestrutura Fase 9", sigla="INF9")
        cargo = Cargo.objects.create(nome="Analista de Redes", departamento=depto)
        localidade = Localidade.objects.create(nome="Salvador F9", codigo="SSA-09", cidade="Salvador", estado="BA")
        self.colaborador = Colaborador.objects.create(
            nome_completo="Paula Progresso",
            matricula="MAT-F9-01",
            email_corporativo="paula.progresso@empresa.com.br",
            departamento=depto,
            cargo=cargo,
            localidade=localidade,
            data_admissao=timezone.localdate(),
            status=Colaborador.StatusColaborador.ATIVO,
        )
        self.sistema = Sistema.objects.create(
            nome="Firewall Fase 9",
            tipo=Sistema.TipoSistema.NETWORK,
            criticidade=Sistema.Criticidade.CRITICA,
        )
        vinculo = VinculoAcesso.objects.create(
            colaborador=self.colaborador,
            sistema=self.sistema,
            identificador_conta="paula.fw",
            concedido_por=responsavel,
        )
        self.processo = ProcessoOffboarding.objects.create(
            colaborador=self.colaborador,
            responsavel_ti=responsavel,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        )
        ItemChecklistOffboarding.objects.create(processo=self.processo, vinculo_acesso=vinculo)

    def test_92_configuracoes_csp_legadas_removidas(self):
        """9.2: nenhuma configuração CSP_* do django-csp 3.x (sem efeito no 4.x) permanece."""
        legadas = [nome for nome in dir(settings) if nome.startswith("CSP_")]
        self.assertEqual(legadas, [])
        self.assertIn("DIRECTIVES", settings.CONTENT_SECURITY_POLICY)

    @override_settings(ALLOWED_HOSTS=["gatekeeper.empresa.com.br"], SECURE_SSL_REDIRECT=True)
    def test_92_healthz_responde_sem_host_permitido_e_sem_https(self):
        """9.2: /healthz/ responde 200 ao curl interno do container (Host 127.0.0.1, HTTP puro)."""
        resp = self.client.get("/healthz/", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b"ok")
        self.assertEqual(resp["Cache-Control"], "no-store")

        # O desvio vale só para /healthz/: as demais rotas continuam validando o host.
        resp_login = self.client.get("/login/", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(resp_login.status_code, 400)

    def test_92_healthz_falha_com_503_quando_banco_indisponivel(self):
        """9.2: sem banco, /healthz/ responde 503 sem expor detalhes do erro."""
        with mock.patch("apps.governance.middleware.connection") as conexao:
            conexao.ensure_connection.side_effect = OperationalError("senha=segredo host=db")
            with self.assertLogs("gatekeeper.audit", level="ERROR"):
                resp = self.client.get("/healthz/")
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.content, b"unavailable")
        self.assertNotIn(b"segredo", resp.content)

    def test_92_healthz_so_aceita_get_e_head(self):
        """9.2: outros métodos seguem a pilha normal (login obrigatório), sem atalho."""
        resp = self.client.post("/healthz/")
        self.assertNotEqual(resp.status_code, 200)

    def test_92_docker_healthcheck_e_caddy(self):
        """9.2: Dockerfile usa /healthz/, Caddy oculta a rota externamente e espera o web saudável."""
        dockerfile = (self.base_dir / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("http://127.0.0.1:8000/healthz/", dockerfile)
        self.assertNotIn("localhost:8000/login/", dockerfile)

        caddyfile = (self.base_dir / "Caddyfile").read_text(encoding="utf-8")
        self.assertIn("respond @healthz 404", caddyfile)

        compose = (self.base_dir / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("web:\n        condition: service_healthy", compose)

    def test_93_template_pr_com_checklist_de_seguranca(self):
        """Template de PR lembra as regras de negar por padrão a cada mudança."""
        template = self.base_dir / ".github" / "pull_request_template.md"
        self.assertTrue(template.exists())
        conteudo = template.read_text(encoding="utf-8")
        for termo in ("rotas_protegidas", "TRANSICOES_PERMITIDAS", 'extra={"audit"', "style=", ".dockerignore", ":?"):
            self.assertIn(termo, conteudo)


class DeploySystemChecksEIntegridadeTests(TestCase):
    def setUp(self):
        self.client = Client()

        self.grupo_analista = Group.objects.get(name="Analista TI")
        self.grupo_gestor = Group.objects.get(name="Gestor SecOps")

        self.user_analista = User.objects.create_user(
            username="analista.p3", email="analista.p3@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.user_analista.groups.add(self.grupo_analista)
        Authenticator.objects.create(
            user=self.user_analista, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        self.user_gestor = User.objects.create_user(
            username="gestor.p3", email="gestor.p3@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.user_gestor.groups.add(self.grupo_gestor)
        Authenticator.objects.create(
            user=self.user_gestor, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        self.superuser = User.objects.create_superuser(
            username="admin.p3", email="admin.p3@empresa.com.br", password="ComplexPassword123!"
        )
        Authenticator.objects.create(
            user=self.superuser, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

        # Dados de apoio
        self.loc = Localidade.objects.create(nome="Recife", codigo="PE-REC", cidade="Recife", estado="PE")
        self.dept = Departamento.objects.create(nome="Segurança", sigla="SEC")
        self.cargo = Cargo.objects.create(nome="Engenheiro", departamento=self.dept)
        self.colab = Colaborador.objects.create(
            nome_completo="Lucas Alvo",
            matricula="SEC-0099",
            email_corporativo="lucas@empresa.com.br",
            departamento=self.dept,
            cargo=self.cargo,
            localidade=self.loc,
            data_admissao="2026-01-01",
        )
        self.sis = Sistema.objects.create(
            nome="GitLab Interno", tipo=Sistema.TipoSistema.SAAS, criticidade=Sistema.Criticidade.ALTA
        )
        self.vinculo = VinculoAcesso.objects.create(
            colaborador=self.colab,
            sistema=self.sis,
            identificador_conta="lucas.git",
            status=VinculoAcesso.StatusAcesso.ATIVO,
        )
        self.processo = ProcessoOffboarding.objects.create(
            colaborador=self.colab,
            responsavel_ti=self.user_gestor,
            status=ProcessoOffboarding.StatusOffboarding.INICIADO,
        )
        self.item = ItemChecklistOffboarding.objects.create(
            processo=self.processo,
            vinculo_acesso=self.vinculo,
            status=ItemChecklistOffboarding.StatusItem.PENDENTE,
        )

    def test_103_cache_compartilhado_dbcache(self):
        """10.3: Backend de cache padrão é DatabaseCache compartilhado, não LocMemCache ou DummyCache."""
        backend = settings.CACHES["default"]["BACKEND"]
        self.assertNotIn("LocMemCache", backend)
        self.assertNotIn("DummyCache", backend)
        self.assertIn("DatabaseCache", backend)

    def test_106_system_checks_bloqueiam_configuracoes_inseguras(self):
        """10.6: System checks gatekeeper.E001-E004 barram regressões de segurança com DEBUG=False."""
        from apps.governance.checks import run_gatekeeper_deploy_checks

        # 1. Configuração padrão deve passar sem erros
        with override_settings(DEBUG=False):
            erros = run_gatekeeper_deploy_checks()
            self.assertEqual(erros, [])

        # 2. MFA_TOTP_TOLERANCE > 0 -> gatekeeper.E001
        with override_settings(DEBUG=False, MFA_TOTP_TOLERANCE=1):
            erros = run_gatekeeper_deploy_checks()
            self.assertTrue(any(e.id == "gatekeeper.E001" for e in erros))

        # 3. LocMemCache -> gatekeeper.E002
        with override_settings(
            DEBUG=False, CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
        ):
            erros = run_gatekeeper_deploy_checks()
            self.assertTrue(any(e.id == "gatekeeper.E002" for e in erros))

        # 4. login_failed sem 'key' -> gatekeeper.E003
        with override_settings(DEBUG=False, ACCOUNT_RATE_LIMITS={"login_failed": "10/m/ip"}):
            erros = run_gatekeeper_deploy_checks()
            self.assertTrue(any(e.id == "gatekeeper.E003" for e in erros))

        # 5. MFA_TOTP_INSECURE_BYPASS_CODE ativo com DEBUG=False -> gatekeeper.E004
        with override_settings(DEBUG=False, MFA_TOTP_INSECURE_BYPASS_CODE="000000"):
            erros = run_gatekeeper_deploy_checks()
            self.assertTrue(any(e.id == "gatekeeper.E004" for e in erros))

    def test_111_compose_contem_servico_migrate_com_createcachetable(self):
        """11.1: docker-compose.yml possui serviço migrate com createcachetable e web depende de sua conclusão."""
        compose_path = Path(settings.BASE_DIR) / "docker-compose.yml"
        self.assertTrue(compose_path.exists())
        conteudo = compose_path.read_text(encoding="utf-8")

        self.assertIn("migrate:", conteudo)
        self.assertIn("python manage.py migrate --noinput && python manage.py createcachetable", conteudo)
        self.assertIn("condition: service_completed_successfully", conteudo)

    def test_112_caddyfile_sem_includesubdomains(self):
        """11.2: Caddyfile não contém includeSubDomains no cabeçalho Strict-Transport-Security."""
        caddy_path = Path(settings.BASE_DIR) / "Caddyfile"
        self.assertTrue(caddy_path.exists())
        conteudo = caddy_path.read_text(encoding="utf-8")

        self.assertNotIn("includeSubDomains", conteudo)
        self.assertIn('Strict-Transport-Security "max-age=31536000"', conteudo)

    def test_113_script_backup_atomico_e_sem_senha_cli(self):
        """11.3: scripts/backup_db.sh não passa DATABASE_URL ao pg_dump e utiliza arquivo .partial com trap."""
        script_path = Path(settings.BASE_DIR) / "scripts" / "backup_db.sh"
        self.assertTrue(script_path.exists())
        conteudo = script_path.read_text(encoding="utf-8")

        self.assertNotIn('pg_dump --format=custom "${DATABASE_URL}"', conteudo)
        self.assertIn("pg_dump --format=custom", conteudo)
        self.assertIn('PARTIAL_FILE="${FINAL_FILE}.partial"', conteudo)
        self.assertIn("trap 'rm -f \"${PARTIAL_FILE}\"' EXIT", conteudo)
        self.assertIn('mv "${PARTIAL_FILE}" "${FINAL_FILE}"', conteudo)

    def test_114_csp_contem_base_uri_e_object_src_none(self):
        """11.4: CSP possui diretivas base-uri 'none' e object-src 'none' em settings e nos headers."""
        directives = settings.CONTENT_SECURITY_POLICY["DIRECTIVES"]
        self.assertEqual(directives.get("base-uri"), ["'none'"])
        self.assertEqual(directives.get("object-src"), ["'none'"])

        resp = self.client.get("/login/")
        csp_header = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("base-uri 'none'", csp_header)
        self.assertIn("object-src 'none'", csp_header)


class DeployCacheTableEComposeChecksTests(TestCase):
    def setUp(self):
        setup_fase10_fixtures(self)
        self.user_auditor = User.objects.create_user(
            username="auditor.rev", email="auditor.rev@empresa.com.br", password="ComplexPassword123!", is_staff=True
        )
        self.user_auditor.groups.add(Group.objects.get(name="Auditor"))
        Authenticator.objects.create(
            user=self.user_auditor, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"}
        )

    def test_r1_migrate_cria_tabela_de_cache(self):
        """R1: a migração recria a tabela do DatabaseCache quando ela não existe."""
        import importlib

        from django.core.cache import cache
        from django.db import connection

        tabela = settings.CACHES["default"]["LOCATION"]
        with connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE {connection.ops.quote_name(tabela)}")  # nosec B608 - nome vem do settings
        self.assertNotIn(tabela, connection.introspection.table_names())

        migracao = importlib.import_module("apps.governance.migrations.0007_criar_tabela_cache")
        migracao.criar_tabela_cache(None, connection.schema_editor())

        self.assertIn(tabela, connection.introspection.table_names())
        cache.set("gk-r1", "ok")
        self.assertEqual(cache.get("gk-r1"), "ok")

    def test_r2_compose_roda_check_deploy_antes_do_migrate(self):
        """R2: o serviço migrate falha (e o web não sobe) se o check --deploy acusar erro."""
        conteudo = (Path(settings.BASE_DIR) / "docker-compose.yml").read_text(encoding="utf-8")
        comando = "python manage.py check --deploy --fail-level ERROR && python manage.py migrate --noinput"
        self.assertIn(comando, conteudo)


class DeployPreparacaoPublicoTests(TestCase):
    @override_settings(DEBUG=True)
    def test_p1_create_root_gera_senha_aleatoria(self):
        """P1: cada execução gera senha nova e imprevisível; a antiga deixa de funcionar."""
        from io import StringIO

        senhas = []
        for _ in range(2):
            saida = StringIO()
            call_command("create_root", stdout=saida)
            senha = re.search(r"Senha:\s+(\S+)", saida.getvalue()).group(1)
            self.assertGreaterEqual(len(senha), 20)
            senhas.append(senha)

        self.assertNotEqual(senhas[0], senhas[1])
        root = User.objects.get(username="root")
        self.assertTrue(root.check_password(senhas[1]))
        self.assertFalse(root.check_password(senhas[0]))

        codigo = (Path(settings.BASE_DIR) / "apps/governance/management/commands/create_root.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("RootDev2026!", codigo)

    def test_p2_time_zone_configuravel_por_ambiente(self):
        """P2: TIME_ZONE vem do ambiente (settings e compose), com padrão documentado no .env.example."""
        base = Path(settings.BASE_DIR)
        self.assertIn('TIME_ZONE = env("TIME_ZONE"', (base / "core/settings.py").read_text(encoding="utf-8"))
        self.assertIn("TIME_ZONE: ${TIME_ZONE:-", (base / "docker-compose.yml").read_text(encoding="utf-8"))
        self.assertIn("TIME_ZONE=", (base / ".env.example").read_text(encoding="utf-8"))
