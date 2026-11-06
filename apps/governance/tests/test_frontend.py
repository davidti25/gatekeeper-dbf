"""
Testes do módulo de Governança & IAM - GateKeeper-DBF.
"""

import re
from pathlib import Path

from allauth.mfa.models import Authenticator
from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
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

User = get_user_model()


class FrontendTemplatesEProgressTests(TestCase):
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

    def test_91_templates_sem_style_nem_handlers_inline(self):
        """9.1 (catraca): nenhum template usa style="" ou on*="" — ambos seriam bloqueados pela CSP."""
        padrao_style = re.compile(r"\sstyle\s*=", re.IGNORECASE)
        padrao_handler = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
        violacoes = []
        for template in (self.base_dir / "templates").rglob("*.html"):
            conteudo = template.read_text(encoding="utf-8")
            if padrao_style.search(conteudo) or padrao_handler.search(conteudo):
                violacoes.append(str(template.relative_to(self.base_dir)))
        self.assertEqual(violacoes, [], "Templates com estilo/JS inline (bloqueados pela CSP)")

    def test_91_paginas_renderizam_progress_nativo_sem_style(self):
        """9.1: as quatro telas com barra de progresso usam <progress> e carregam o CSS único compilado."""
        self.client.force_login(self.user_auditor)
        rotas = [
            reverse("dashboard"),
            reverse("offboarding_list"),
            reverse("offboarding_detail", kwargs={"pk": self.processo.pk}),
            reverse("colaborador_detail", kwargs={"pk": self.colaborador.pk}),
        ]
        for rota in rotas:
            resp = self.client.get(rota)
            self.assertEqual(resp.status_code, 200, rota)
            conteudo = resp.content.decode()
            self.assertIn('<progress class="gk-progress', conteudo, rota)
            self.assertIn('max="100"', conteudo, rota)
            self.assertNotIn("style=", conteudo, rota)
            self.assertIn("css/tailwind.min.", conteudo, rota)

    def test_91_admin_selos_e_progresso_por_classe_css(self):
        """9.1: selos e progresso do admin não geram style="" e o admin carrega css/admin.css."""
        sistema_admin = admin.site._registry[Sistema]
        colaborador_admin = admin.site._registry[Colaborador]
        vinculo_admin = admin.site._registry[VinculoAcesso]
        processo_admin = admin.site._registry[ProcessoOffboarding]

        html_gerado = [
            sistema_admin.exibir_criticidade(self.sistema),
            colaborador_admin.exibir_status(self.colaborador),
            vinculo_admin.exibir_status(VinculoAcesso.objects.first()),
            processo_admin.exibir_status(self.processo),
            processo_admin.exibir_progresso(self.processo),
        ]
        for html in html_gerado:
            self.assertNotIn("style=", html)

        self.assertIn('class="gk-badge gk-badge--vermelho"', html_gerado[0])  # criticidade CRITICA
        self.assertIn('class="gk-badge gk-badge--verde"', html_gerado[1])  # colaborador ATIVO
        self.assertIn('<progress class="gk-admin-progress"', html_gerado[4])

        for model_admin in (sistema_admin, colaborador_admin, vinculo_admin, processo_admin):
            self.assertIn("/static/css/admin.", str(model_admin.media))


class CSSConsistencyAndAccessibilityTests(TestCase):
    def setUp(self):
        self.base_dir = Path(settings.BASE_DIR)
        self.css_dir = self.base_dir / "static" / "css"
        self.compilado = (self.css_dir / "tailwind.min.css").read_text(encoding="utf-8")

    def _classes_gk_usadas(self):
        fontes = list((self.base_dir / "templates").rglob("*.html"))
        fontes.append(self.base_dir / "apps" / "governance" / "forms.py")
        classes = set()
        for fonte in fontes:
            conteudo = fonte.read_text(encoding="utf-8")
            for valor in re.findall(r'class(?:="|": ")([^"]*)"', conteudo):
                classes.update(re.findall(r"(?<![\w-])gk-[a-z0-9-]+", valor))
        return classes

    def test_css_todo_componente_gk_usado_existe(self):
        """Uma classe gk-* usada sem definição no CSS ficaria sem estilo em produção."""
        admin_css = (self.css_dir / "admin.css").read_text(encoding="utf-8")
        usadas = self._classes_gk_usadas()
        self.assertTrue(usadas, "Nenhum componente gk-* encontrado nos templates")
        # A classe pode aparecer seguida de {, ",", ":", ">", espaço etc. (ex.: `.gk-allauth>…`).
        faltando = sorted(
            c
            for c in usadas
            if not re.search(rf"\.{re.escape(c)}(?![\w-])", self.compilado)
            and not re.search(rf"\.{re.escape(c)}(?![\w-])", admin_css)
        )
        self.assertEqual(faltando, [], "Componentes usados nos templates sem definição no CSS compilado")

    def test_css_fonte_unica_sem_arquivos_soltos(self):
        """components.css e print.css foram incorporados ao input.css; templates só carregam o CSS compilado."""
        self.assertFalse((self.css_dir / "components.css").exists())
        self.assertFalse((self.css_dir / "print.css").exists())
        permitidos = {"fonts/fonts.css", "css/tailwind.min.css"}
        for template in (self.base_dir / "templates").rglob("*.html"):
            for href in re.findall(
                r"""<link rel="stylesheet" href="\{% static '([^']+)' %\}">""", template.read_text(encoding="utf-8")
            ):
                self.assertIn(href, permitidos, f"{template.name} carrega CSS fora da fonte única: {href}")
        # Regras de impressão do relatório agora vêm do CSS compilado
        self.assertIn("@media print", self.compilado)
        self.assertIn(".no-print", self.compilado)

    def test_css_acessibilidade(self):
        """Foco visível (WCAG 2.4.7), menos movimento (WCAG 2.3.3) e controles nativos no tema escuro."""
        self.assertIn(":focus-visible", self.compilado)
        self.assertIn("prefers-reduced-motion:reduce", self.compilado)
        self.assertIn("color-scheme:dark", self.compilado)
        self.assertIn("scrollbar-color", self.compilado)  # Firefox
        base = (self.base_dir / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertIn('<html lang="pt-BR" class="gk-dark', base)

    def test_css_progress_com_prefixos_em_regras_separadas(self):
        """Seletores -webkit- e -moz- na mesma lista fazem o navegador descartar a regra inteira."""
        misturados = re.findall(r"[^{}]*-webkit-progress[^{}]*-moz-progress[^{}]*\{", self.compilado)
        misturados += re.findall(r"[^{}]*-moz-progress[^{}]*-webkit-progress[^{}]*\{", self.compilado)
        self.assertEqual(misturados, [])
        self.assertIn(".gk-progress--done::-webkit-progress-value{", self.compilado)
        self.assertIn(".gk-progress--done::-moz-progress-bar{", self.compilado)

    def test_css_cores_do_tema_sem_hex_solto(self):
        """No input.css as cores vêm de theme(...), para não divergirem da paleta do Tailwind."""
        fonte = (self.css_dir / "input.css").read_text(encoding="utf-8")
        sem_comentarios = re.sub(r"/\*.*?\*/", "", fonte, flags=re.S)
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b", sem_comentarios), [])

    def test_css_build_reprodutivel_e_verificado(self):
        """Binário do Tailwind com versão fixa e SHA-256; CI e pre-commit falham com CSS desatualizado."""
        script = (self.base_dir / "scripts" / "build_css.sh").read_text(encoding="utf-8")
        self.assertIn('TAILWIND_VERSION="3.4.17"', script)
        self.assertIn("7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4", script)  # linux-x64
        self.assertIn("checksum SHA-256 do binário não confere", script)

        ci = (self.base_dir / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/build_css.sh --check", ci)

        pre_commit = (self.base_dir / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        self.assertIn("scripts/build_css.sh --check", pre_commit)


class AllauthStylingTests(TestCase):
    SENHA = "Xk9!vQ2#mLp7zRr"

    def setUp(self):
        self.base_dir = Path(settings.BASE_DIR)
        self.user = User.objects.create_user("staff.allauth", "staff.allauth@empresa.com.br", self.SENHA, is_staff=True)

    def _login_reautenticado(self):
        self.client.post("/login/", {"login": self.user.username, "password": self.SENHA})
        self.client.post("/accounts/reauthenticate/", {"password": self.SENHA})

    def test_layout_allauth_envolve_content_pelo_bloco_main(self):
        """O cartão fica em `main`; a página do allauth preenche `content` dentro dele."""
        base = (self.base_dir / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertIn("{% block main %}{% block content %}{% endblock %}{% endblock %}", base)
        for layout in ("entrance.html", "manage.html"):
            conteudo = (self.base_dir / "templates" / "allauth" / "layouts" / layout).read_text(encoding="utf-8")
            self.assertIn("{% block main %}", conteudo, layout)
            self.assertIn("{% block content %}{% endblock %}", conteudo, layout)

    def test_tela_ativar_totp_estilizada(self):
        """A tela do print do bug: cartão, título, QR com fundo claro, segredo copiável, campo e botão estilizados."""
        self._login_reautenticado()
        resp = self.client.get(reverse("mfa_activate_totp"))
        self.assertEqual(resp.status_code, 200)
        html = resp.content.decode()
        for esperado in (
            'class="gk-auth-card gk-allauth"',
            'class="gk-h1"',
            'class="gk-text"',
            'class="gk-qr"',
            'class="gk-field-control"',
            'class="gk-btn-primary"',
        ):
            self.assertIn(esperado, html)
        # Segredo sem `name` (não vai no POST): readonly para poder ser copiado
        segredo = re.search(r'<input[^>]*id="authenticator_secret"[^>]*>', html, re.S).group(0)
        self.assertIn("readonly", segredo)
        self.assertNotIn("disabled", segredo)
        self.assertNotIn("style=", html)
        self.assertNotIn("{% comment", html)

    def test_demais_telas_allauth_usam_cartao_e_elementos(self):
        """Telas de gestão de MFA e conta renderizam no cartão, com título e botões do GateKeeper."""
        # TOTP ativado depois do login: antes dele, o login passaria a exigir o código de MFA.
        self._login_reautenticado()
        Authenticator.objects.create(user=self.user, type=Authenticator.Type.TOTP, data={"secret": "JBSWY3DPEHPK3PXP"})
        for nome in ("mfa_index", "mfa_deactivate_totp", "account_change_password", "account_reauthenticate"):
            resp = self.client.get(reverse(nome))
            self.assertEqual(resp.status_code, 200, nome)
            html = resp.content.decode()
            self.assertIn("gk-auth-card", html, nome)
            self.assertIn('class="gk-h1"', html, nome)
            self.assertIn("gk-btn-", html, nome)
            self.assertNotIn("style=", html, nome)

    def test_variantes_de_botao_pelos_tags_do_allauth(self):
        """danger > link > secundário > primário (sem tags); `tool` usa o tamanho pequeno."""
        from django.template import Context, Origin, Template

        # O allauth usa o nome do template de origem para resolver o elemento.
        origem = Origin(name="teste_botao.html", template_name="teste_botao.html")

        casos = {
            'tags="danger,delete"': "gk-btn-danger",
            'tags="link,cancel"': "gk-btn-link",
            'tags="outline,primary"': "gk-btn-secondary",
            'tags="mfa,authenticator,edit,tool"': "gk-btn-secondary gk-btn-sm",
            'tags="prominent,login"': "gk-btn-primary",
            "": "gk-btn-primary",
        }
        for tags, classe in casos.items():
            html = Template(
                "{% load allauth %}{% element button type='submit' " + tags + " %}OK{% endelement %}",
                origin=origem,
            ).render(Context({}))
            self.assertIn(f'class="{classe}"', html, tags or "(sem tags)")
