"""
Management Command para popular dados base (seed) de Governança & IAM.

Popula:
- Localidades
- Departamentos
- Cargos
- Sistemas e Perfis
- Colaboradores demonstrativos
- Concessão de Acessos (Matriz RBAC)
- Processo de Offboarding em andamento e concluído

Uso:
    python manage.py seed_governance
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta, date
from django.conf import settings
from apps.governance.models import (
    Localidade,
    Departamento,
    Cargo,
    Sistema,
    PerfilAcesso,
    Colaborador,
    VinculoAcesso,
    ProcessoOffboarding,
    ItemChecklistOffboarding,
)

User = get_user_model()


class Command(BaseCommand):
    help = "Popula o banco de dados com a estrutura completa e dados de demonstração para Governança e Offboarding."

    def handle(self, *args, **options):
        # Proteção DevSecOps: Bloqueio estrito em produção
        if not settings.DEBUG:
            self.stderr.write(self.style.ERROR("❌ ERRO DE SEGURANÇA: seed_governance é exclusivo para ambientes de desenvolvimento (DEBUG=True)."))
            return

        self.stdout.write(self.style.NOTICE("Iniciando carga de dados base de Governança & IAM..."))

        # 0. Resolução de Usuário Técnico para Vínculos (Sem credenciais estáticas)
        admin_user = User.objects.filter(is_superuser=True).first() or User.objects.first()
        if not admin_user:
            admin_user = User.objects.create(
                username="sistema.automacao",
                email="automacao@gatekeeper.local",
                is_staff=False,
                is_active=False  # Conta desativada e sem senha (impossível efetuar login)
            )
            admin_user.set_unusable_password()
            admin_user.save()

        # 1. Localidades
        localidades_data = [
            {"nome": "Matriz - São Paulo", "codigo": "SP-MATRIZ", "cidade": "São Paulo", "estado": "SP"},
            {"nome": "Filial - Rio de Janeiro", "codigo": "RJ-01", "cidade": "Rio de Janeiro", "estado": "RJ"},
            {"nome": "Operação Remota / Home Office", "codigo": "REMOTO", "cidade": "São Paulo", "estado": "SP"},
        ]
        localidades = {}
        for loc in localidades_data:
            obj, _ = Localidade.objects.get_or_create(
                codigo=loc["codigo"],
                defaults=loc
            )
            localidades[loc["codigo"]] = obj

        # 2. Departamentos
        deptos_data = [
            {"nome": "Tecnologia da Informação & SecOps", "sigla": "TI", "descricao": "Infraestrutura, Segurança da Informação e Suporte"},
            {"nome": "Recursos Humanos & DP", "sigla": "RH", "descricao": "Gestão de Pessoas, Admissão e Desligamento"},
            {"nome": "Financeiro & Controladoria", "sigla": "FIN", "descricao": "Contas a Pagar/Receber, Tesouraria e Faturamento"},
            {"nome": "Comercial & Vendas", "sigla": "COM", "descricao": "Prospecção, Atendimento e Negociações"},
            {"nome": "Operações & Logística", "sigla": "LOG", "descricao": "Cadeia de Suprimentos e Distribuição"},
        ]
        deptos = {}
        for dep in deptos_data:
            obj, _ = Departamento.objects.get_or_create(
                sigla=dep["sigla"],
                defaults=dep
            )
            deptos[dep["sigla"]] = obj

        # 3. Cargos
        cargos_data = [
            {"nome": "Analista de Segurança da Informação / SOC", "departamento": deptos["TI"]},
            {"nome": "Analista de Suporte e Infraestrutura", "departamento": deptos["TI"]},
            {"nome": "Coordenador de TI", "departamento": deptos["TI"]},
            {"nome": "Analista de Recursos Humanos", "departamento": deptos["RH"]},
            {"nome": "Assistente de Departamento Pessoal", "departamento": deptos["RH"]},
            {"nome": "Assistente Financeiro", "departamento": deptos["FIN"]},
            {"nome": "Analista de Controladoria", "departamento": deptos["FIN"]},
            {"nome": "Executivo de Vendas", "departamento": deptos["COM"]},
            {"nome": "Assistente de Logística", "departamento": deptos["LOG"]},
        ]
        cargos = {}
        for car in cargos_data:
            obj, _ = Cargo.objects.get_or_create(
                nome=car["nome"],
                departamento=car["departamento"],
                defaults=car
            )
            cargos[car["nome"]] = obj

        # 4. Sistemas Corporativos & Perfis
        sistemas_data = [
            {
                "nome": "Google Workspace (Gmail / Drive / Meet)",
                "tipo": Sistema.TipoSistema.SAAS,
                "criticidade": Sistema.Criticidade.ALTA,
                "armazena_dados_lgpd": True,
                "tipo_autenticacao": Sistema.TipoAutenticacao.INDIVIDUAL,
                "acesso_externo": Sistema.AcessoExterno.INTERNET,
                "gestor_responsavel": "Equipe de TI",
                "link_painel_admin": "https://admin.google.com",
                "instrucoes_revogacao": "Acessar console Google Workspace -> Usuários -> Suspender Usuário -> Revogar tokens de aplicativos móveis -> Transferir propriedade de arquivos críticos do Google Drive.",
                "perfis": [
                    ("Usuário Padrão", PerfilAcesso.NivelPrivilegio.OPERADOR),
                    ("Super Administrador", PerfilAcesso.NivelPrivilegio.ADMIN),
                ]
            },
            {
                "nome": "VPN Corporativa (WireGuard / OpenVPN)",
                "tipo": Sistema.TipoSistema.VPN,
                "criticidade": Sistema.Criticidade.CRITICA,
                "armazena_dados_lgpd": False,
                "tipo_autenticacao": Sistema.TipoAutenticacao.INDIVIDUAL,
                "acesso_externo": Sistema.AcessoExterno.INTERNET,
                "gestor_responsavel": "SecOps / Infraestrutura TI",
                "instrucoes_revogacao": "Remover chave pública do peer no servidor WireGuard (/etc/wireguard/wg0.conf) e revogar certificado cliente na CA OpenVPN.",
                "perfis": [
                    ("Acesso Rede Corporativa (Colaborador)", PerfilAcesso.NivelPrivilegio.OPERADOR),
                    ("Acesso DMZ & Gerenciamento (TI)", PerfilAcesso.NivelPrivilegio.ADMIN),
                ]
            },
            {
                "nome": "Roteadores MikroTik (Winbox / SSH)",
                "tipo": Sistema.TipoSistema.NETWORK,
                "criticidade": Sistema.Criticidade.CRITICA,
                "armazena_dados_lgpd": False,
                "tipo_autenticacao": Sistema.TipoAutenticacao.INDIVIDUAL,
                "acesso_externo": Sistema.AcessoExterno.SOMENTE_VPN,
                "gestor_responsavel": "Administrador de Redes / SecOps",
                "instrucoes_revogacao": "Acessar via Winbox ou SSH (/user), executar 'remove [find name=usuario]' ou 'disable [find name=usuario]'. Revogar chave SSH pública se vinculada.",
                "perfis": [
                    ("Read-Only (Monitoramento NOC)", PerfilAcesso.NivelPrivilegio.LEITURA),
                    ("Full Admin (Engenharia de Redes)", PerfilAcesso.NivelPrivilegio.ADMIN),
                ]
            },
            {
                "nome": "ERP Corporativo (Faturamento & Financeiro)",
                "tipo": Sistema.TipoSistema.SAAS,
                "criticidade": Sistema.Criticidade.CRITICA,
                "armazena_dados_lgpd": True,
                "tipo_autenticacao": Sistema.TipoAutenticacao.INDIVIDUAL,
                "acesso_externo": Sistema.AcessoExterno.INTERNET,
                "gestor_responsavel": "TI Interna & Consultoria ERP",
                "instrucoes_revogacao": "Acessar Módulo Configurador -> Usuários -> Inativar cadastro do usuário e revogar licença de acesso aos módulos fiscais.",
                "perfis": [
                    ("Consulta / Relatórios", PerfilAcesso.NivelPrivilegio.LEITURA),
                    ("Operador Financeiro / Contas a Pagar", PerfilAcesso.NivelPrivilegio.OPERADOR),
                    ("Gestor Financeiro / Aprovação de Pagamentos", PerfilAcesso.NivelPrivilegio.SUPERVISOR),
                    ("Administrador do Sistema", PerfilAcesso.NivelPrivilegio.ADMIN),
                ]
            },
            {
                "nome": "Servidor de Arquivos SMB (Storage Local)",
                "tipo": Sistema.TipoSistema.PASTA_REDE,
                "criticidade": Sistema.Criticidade.MEDIA,
                "armazena_dados_lgpd": True,
                "tipo_autenticacao": Sistema.TipoAutenticacao.SSO_AD,
                "acesso_externo": Sistema.AcessoExterno.REDE_LOCAL,
                "gestor_responsavel": "Equipe de Suporte TI",
                "instrucoes_revogacao": "Remover o usuário de todos os grupos de segurança no Active Directory (AD) e encerrar sessões SMB ativas no servidor.",
                "perfis": [
                    ("Leitura Compartilhada", PerfilAcesso.NivelPrivilegio.LEITURA),
                    ("Modificação / Escrita do Setor", PerfilAcesso.NivelPrivilegio.OPERADOR),
                ]
            },
        ]

        sistemas = {}
        perfis_map = {}
        for sis_info in sistemas_data:
            perfis = sis_info.pop("perfis")
            sis_obj, _ = Sistema.objects.get_or_create(
                nome=sis_info["nome"],
                defaults=sis_info
            )
            sistemas[sis_obj.nome] = sis_obj

            for p_nome, p_nivel in perfis:
                p_obj, _ = PerfilAcesso.objects.get_or_create(
                    sistema=sis_obj,
                    nome=p_nome,
                    defaults={"nivel_privilegio": p_nivel}
                )
                perfis_map[(sis_obj.nome, p_nome)] = p_obj

        # 5. Colaboradores de Demonstração
        colabs_data = [
            {
                "nome_completo": "Lucas Silveira Oliveira",
                "matricula": "SEC-0101",
                "email_corporativo": "lucas.silveira@empresa.com.br",
                "cargo": cargos["Analista de Segurança da Informação / SOC"],
                "departamento": deptos["TI"],
                "localidade": localidades["SP-MATRIZ"],
                "status": Colaborador.StatusColaborador.ATIVO,
                "data_admissao": date(2025, 2, 10),
            },
            {
                "nome_completo": "Mariana Souza Duarte",
                "matricula": "FIN-0082",
                "email_corporativo": "mariana.souza@empresa.com.br",
                "cargo": cargos["Analista de Controladoria"],
                "departamento": deptos["FIN"],
                "localidade": localidades["SP-MATRIZ"],
                "status": Colaborador.StatusColaborador.ATIVO,
                "data_admissao": date(2024, 8, 15),
            },
            {
                "nome_completo": "Rodrigo Mendes Castro",
                "matricula": "COM-0055",
                "email_corporativo": "rodrigo.mendes@empresa.com.br",
                "cargo": cargos["Executivo de Vendas"],
                "departamento": deptos["COM"],
                "localidade": localidades["REMOTO"],
                "status": Colaborador.StatusColaborador.ATIVO,  # Em processo de offboarding
                "data_admissao": date(2024, 1, 20),
            },
            {
                "nome_completo": "Beatriz Lima Fernandes",
                "matricula": "RH-0023",
                "email_corporativo": "beatriz.lima@empresa.com.br",
                "cargo": cargos["Assistente de Departamento Pessoal"],
                "departamento": deptos["RH"],
                "localidade": localidades["RJ-01"],
                "status": Colaborador.StatusColaborador.DESLIGADO,
                "data_admissao": date(2023, 6, 1),
                "data_desligamento": date(2026, 10, 30),
            },
        ]

        colabs = {}
        for c_data in colabs_data:
            c_obj, _ = Colaborador.objects.get_or_create(
                email_corporativo=c_data["email_corporativo"],
                defaults=c_data
            )
            colabs[c_obj.email_corporativo] = c_obj

        # 6. Concessões de Acessos (Matriz RBAC)
        # Lucas (SOC): Google Workspace, VPN, MikroTik
        VinculoAcesso.objects.get_or_create(
            colaborador=colabs["lucas.silveira@empresa.com.br"],
            sistema=sistemas["Google Workspace (Gmail / Drive / Meet)"],
            identificador_conta="lucas.silveira@empresa.com.br",
            defaults={"perfil_acesso": perfis_map[("Google Workspace (Gmail / Drive / Meet)", "Usuário Padrão")], "concedido_por": admin_user}
        )
        VinculoAcesso.objects.get_or_create(
            colaborador=colabs["lucas.silveira@empresa.com.br"],
            sistema=sistemas["VPN Corporativa (WireGuard / OpenVPN)"],
            identificador_conta="lucas.secops",
            defaults={"perfil_acesso": perfis_map[("VPN Corporativa (WireGuard / OpenVPN)", "Acesso DMZ & Gerenciamento (TI)")], "concedido_por": admin_user}
        )
        VinculoAcesso.objects.get_or_create(
            colaborador=colabs["lucas.silveira@empresa.com.br"],
            sistema=sistemas["Roteadores MikroTik (Winbox / SSH)"],
            identificador_conta="lucas.silveira",
            defaults={"perfil_acesso": perfis_map[("Roteadores MikroTik (Winbox / SSH)", "Full Admin (Engenharia de Redes)")], "concedido_por": admin_user}
        )

        # Mariana (Financeiro): Google Workspace, ERP, File Server
        VinculoAcesso.objects.get_or_create(
            colaborador=colabs["mariana.souza@empresa.com.br"],
            sistema=sistemas["Google Workspace (Gmail / Drive / Meet)"],
            identificador_conta="mariana.souza@empresa.com.br",
            defaults={"perfil_acesso": perfis_map[("Google Workspace (Gmail / Drive / Meet)", "Usuário Padrão")], "concedido_por": admin_user}
        )
        VinculoAcesso.objects.get_or_create(
            colaborador=colabs["mariana.souza@empresa.com.br"],
            sistema=sistemas["ERP Corporativo (Faturamento & Financeiro)"],
            identificador_conta="mariana.souza",
            defaults={"perfil_acesso": perfis_map[("ERP Corporativo (Faturamento & Financeiro)", "Gestor Financeiro / Aprovação de Pagamentos")], "concedido_por": admin_user}
        )
        VinculoAcesso.objects.get_or_create(
            colaborador=colabs["mariana.souza@empresa.com.br"],
            sistema=sistemas["Servidor de Arquivos SMB (Storage Local)"],
            identificador_conta="msouza",
            defaults={"perfil_acesso": perfis_map[("Servidor de Arquivos SMB (Storage Local)", "Modificação / Escrita do Setor")], "concedido_por": admin_user}
        )

        # Rodrigo (Comercial - Offboarding em Andamento): Google Workspace, VPN, ERP
        v_rodrigo_gsuite, _ = VinculoAcesso.objects.get_or_create(
            colaborador=colabs["rodrigo.mendes@empresa.com.br"],
            sistema=sistemas["Google Workspace (Gmail / Drive / Meet)"],
            identificador_conta="rodrigo.mendes@empresa.com.br",
            defaults={"perfil_acesso": perfis_map[("Google Workspace (Gmail / Drive / Meet)", "Usuário Padrão")], "concedido_por": admin_user}
        )
        v_rodrigo_vpn, _ = VinculoAcesso.objects.get_or_create(
            colaborador=colabs["rodrigo.mendes@empresa.com.br"],
            sistema=sistemas["VPN Corporativa (WireGuard / OpenVPN)"],
            identificador_conta="rodrigo.mendes",
            defaults={"perfil_acesso": perfis_map[("VPN Corporativa (WireGuard / OpenVPN)", "Acesso Rede Corporativa (Colaborador)")], "concedido_por": admin_user}
        )

        # Processo de Offboarding para Rodrigo (1 de 2 revogados)
        proc_rodrigo, _ = ProcessoOffboarding.objects.get_or_create(
            colaborador=colabs["rodrigo.mendes@empresa.com.br"],
            defaults={
                "responsavel_ti": admin_user,
                "status": ProcessoOffboarding.StatusOffboarding.INICIADO,
                "observacoes": "Desligamento por iniciativa do colaborador",
            }
        )
        # Item 1: VPN revogada
        item_vpn, _ = ItemChecklistOffboarding.objects.get_or_create(
            processo=proc_rodrigo,
            vinculo_acesso=v_rodrigo_vpn,
            defaults={
                "revogado": True,
                "data_revogacao": timezone.now() - timedelta(hours=2),
                "responsavel_revogacao": admin_user,
                "evidencia_revogacao": "Chave pública WireGuard desativada via Ansible. Chamado GLPI #8821",
            }
        )
        # Atualiza vínculo da VPN de Rodrigo como revogado
        v_rodrigo_vpn.status = VinculoAcesso.StatusAcesso.REVOGADO
        v_rodrigo_vpn.data_revogacao = timezone.now() - timedelta(hours=2)
        v_rodrigo_vpn.revogado_por = admin_user
        v_rodrigo_vpn.save()

        # Item 2: Google Workspace pendente
        ItemChecklistOffboarding.objects.get_or_create(
            processo=proc_rodrigo,
            vinculo_acesso=v_rodrigo_gsuite,
            defaults={"revogado": False}
        )

        # Beatriz (RH - Offboarding 100% Concluído e Auditado)
        v_beatriz_gsuite, _ = VinculoAcesso.objects.get_or_create(
            colaborador=colabs["beatriz.lima@empresa.com.br"],
            sistema=sistemas["Google Workspace (Gmail / Drive / Meet)"],
            identificador_conta="beatriz.lima@empresa.com.br",
            defaults={
                "perfil_acesso": perfis_map[("Google Workspace (Gmail / Drive / Meet)", "Usuário Padrão")],
                "status": VinculoAcesso.StatusAcesso.REVOGADO,
                "data_revogacao": timezone.now() - timedelta(days=6),
                "revogado_por": admin_user,
                "justificativa": "Offboarding concluído",
            }
        )
        proc_beatriz, _ = ProcessoOffboarding.objects.get_or_create(
            colaborador=colabs["beatriz.lima@empresa.com.br"],
            defaults={
                "responsavel_ti": admin_user,
                "status": ProcessoOffboarding.StatusOffboarding.CONCLUIDO,
                "concluido_em": timezone.now() - timedelta(days=6),
                "observacoes": "Término de contrato",
            }
        )
        ItemChecklistOffboarding.objects.get_or_create(
            processo=proc_beatriz,
            vinculo_acesso=v_beatriz_gsuite,
            defaults={
                "revogado": True,
                "data_revogacao": timezone.now() - timedelta(days=6),
                "responsavel_revogacao": admin_user,
                "evidencia_revogacao": "Conta Google suspensa e backup de e-mails concluído. Chamado GLPI #8750",
            }
        )

        self.stdout.write(self.style.SUCCESS("✅ Carga completa com demonstração de Governança & Offboarding concluída com sucesso!"))
