#!/usr/bin/env python3
"""
Script utilitário para higienização e limpeza de dados fictícios de teste.

Regras de Segurança:
- NUNCA remove superusuários (ex: admin.secops, root).
- NUNCA remove grupos de permissão e catraca RBAC.
- Exige argumento explícito --confirmar para executar a limpeza no banco.
- Execução em transação atômica única (tudo ou nada).
"""

import os
import sys

import django

# Setup Django Environment
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from django.db import transaction  # noqa: E402

from apps.governance.models import (  # noqa: E402
    CampanhaRevisao,
    Cargo,
    Colaborador,
    Departamento,
    ItemChecklistOffboarding,
    ItemRevisao,
    Localidade,
    PerfilAcesso,
    ProcessoOffboarding,
    Sistema,
    SolicitacaoAcesso,
    VinculoAcesso,
)


def limpar_dados(confirmar=False):
    print("=" * 70)
    print("🧹 GateKeeper-DBF — Higienização de Dados de Teste")
    print("=" * 70)

    contagens = {
        "Processos Offboarding": ProcessoOffboarding.objects.count(),
        "Itens de Checklist Offboarding": ItemChecklistOffboarding.objects.count(),
        "Campanhas de Revisão": CampanhaRevisao.objects.count(),
        "Itens de Revisão": ItemRevisao.objects.count(),
        "Solicitações de Acesso": SolicitacaoAcesso.objects.count(),
        "Vínculos de Acesso": VinculoAcesso.objects.count(),
        "Colaboradores": Colaborador.objects.count(),
        "Perfis de Acesso": PerfilAcesso.objects.count(),
        "Sistemas": Sistema.objects.count(),
        "Cargos": Cargo.objects.count(),
        "Departamentos": Departamento.objects.count(),
        "Localidades": Localidade.objects.count(),
    }

    print("\n[i] Registros atuais identificados no banco de dados:")
    for entidade, qtd in contagens.items():
        print(f"    - {entidade}: {qtd}")

    if not confirmar:
        print("\n[!] MODO SEGURO: Nenhuma alteração foi realizada.")
        print("[!] Para efetivar a limpeza e zerar a base para dados reais, execute:")
        print("    python scripts/limpar_dados_teste.py --confirmar\n")
        return

    print("\n[*] Iniciando expurgo atômico de dados de teste...")
    with transaction.atomic():
        ItemChecklistOffboarding.objects.all().delete()
        ProcessoOffboarding.objects.all().delete()
        ItemRevisao.objects.all().delete()
        CampanhaRevisao.objects.all().delete()
        SolicitacaoAcesso.objects.all().delete()
        VinculoAcesso.objects.all().delete()
        Colaborador.objects.all().delete()
        PerfilAcesso.objects.all().delete()
        Sistema.objects.all().delete()
        Cargo.objects.all().delete()
        Departamento.objects.all().delete()
        Localidade.objects.all().delete()

    print("[+] Limpeza concluída com sucesso! Banco zerado e pronto para implantação real.")
    print("[+] Contas administrativas e grupos RBAC foram preservados intactos.\n")


if __name__ == "__main__":
    confirmar_execucao = "--confirmar" in sys.argv
    limpar_dados(confirmar=confirmar_execucao)
