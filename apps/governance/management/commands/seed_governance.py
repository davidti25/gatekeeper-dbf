"""
Management Command para popular dados base (seed) de Governança & IAM.

Uso:
    python manage.py seed_governance
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from apps.governance.models import (
    Localidade,
    Departamento,
    Cargo,
    Sistema,
    PerfilAcesso,
)

User = get_user_model()


class Command(BaseCommand):
    help = "Popula o banco de dados com a estrutura inicial de localidades, setores, cargos e sistemas corporativos."

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("Iniciando carga de dados base de Governança..."))

        # 1. Localidades
        localidades_data = [
            {"nome": "Matriz - São Paulo", "codigo": "SP-MATRIZ", "cidade": "São Paulo", "estado": "SP"},
            {"nome": "Filial - Rio de Janeiro", "codigo": "RJ-01", "cidade": "Rio de Janeiro", "estado": "RJ"},
            {"nome": "Operação Remota / Home Office", "codigo": "REMOTO", "cidade": "São Paulo", "estado": "SP"},
        ]
        localidades = {}
        for loc in localidades_data:
            obj, created = Localidade.objects.get_or_create(
                codigo=loc["codigo"],
                defaults=loc
            )
            localidades[loc["codigo"]] = obj
            status = "criada" if created else "já existente"
            self.stdout.write(f"  • Localidade {obj.nome} ({status})")

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
            obj, created = Departamento.objects.get_or_create(
                sigla=dep["sigla"],
                defaults=dep
            )
            deptos[dep["sigla"]] = obj
            status = "criado" if created else "já existente"
            self.stdout.write(f"  • Departamento {obj.nome} ({status})")

        # 3. Cargos
        cargos_data = [
            # TI
            {"nome": "Analista de Segurança da Informação / SOC", "departamento": deptos["TI"]},
            {"nome": "Analista de Suporte e Infraestrutura", "departamento": deptos["TI"]},
            {"nome": "Coordenador de TI", "departamento": deptos["TI"]},
            # RH
            {"nome": "Analista de Recursos Humanos", "departamento": deptos["RH"]},
            {"nome": "Assistente de Departamento Pessoal", "departamento": deptos["RH"]},
            # Financeiro
            {"nome": "Assistente Financeiro", "departamento": deptos["FIN"]},
            {"nome": "Analista de Controladoria", "departamento": deptos["FIN"]},
            # Comercial
            {"nome": "Executivo de Vendas", "departamento": deptos["COM"]},
            # Logística
            {"nome": "Assistente de Logística", "departamento": deptos["LOG"]},
        ]
        for car in cargos_data:
            obj, created = Cargo.objects.get_or_create(
                nome=car["nome"],
                departamento=car["departamento"],
                defaults=car
            )
            status = "criado" if created else "já existente"
            self.stdout.write(f"  • Cargo {obj.nome} ({status})")

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
                "instrucoes_revogacao": "Acessar console Google Workspace -> Usuários -> Suspender Usuário -> Transferir propriedade de arquivos do Drive se necessário.",
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
                "instrucoes_revogacao": "Desativar chave pública do peer no servidor WireGuard e revogar certificado OpenVPN na CA interna.",
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
                "instrucoes_revogacao": "Acessar /user no RouterOS, remover o usuário específico ou desabilitar imediatamente via CLI.",
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
                "instrucoes_revogacao": "Acessar Módulo Configurador -> Usuários -> Inativar cadastro do usuário e revogar licença de uso.",
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
                "instrucoes_revogacao": "Remover membro dos grupos de segurança de pastas no Active Directory.",
                "perfis": [
                    ("Leitura Compartilhada", PerfilAcesso.NivelPrivilegio.LEITURA),
                    ("Modificação / Escrita do Setor", PerfilAcesso.NivelPrivilegio.OPERADOR),
                ]
            },
        ]

        for sis_info in sistemas_data:
            perfis = sis_info.pop("perfis")
            sis_obj, created = Sistema.objects.get_or_create(
                nome=sis_info["nome"],
                defaults=sis_info
            )
            status = "criado" if created else "já existente"
            self.stdout.write(f"  • Sistema {sis_obj.nome} ({status})")

            for p_nome, p_nivel in perfis:
                p_obj, p_created = PerfilAcesso.objects.get_or_create(
                    sistema=sis_obj,
                    nome=p_nome,
                    defaults={"nivel_privilegio": p_nivel}
                )

        self.stdout.write(self.style.SUCCESS("✅ Carga de dados base de Governança concluída com sucesso!"))

