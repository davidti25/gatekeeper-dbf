"""
Comando de Importação de Colaboradores via CSV (Fase 16.3).

Regras de Segurança & Conformidade:
- Validação campo a campo via full_clean() do Django.
- Neutralização de injeção de fórmulas (CSV Formula Injection) em células com [=, +, -, @].
- Modos --simular (padrão) e --aplicar com transação atômica (tudo ou nada).
- Casamento por 'matricula' ou 'email_corporativo'.
- Importação NUNCA desliga colaboradores — ausentes no CSV são reportados como 'a verificar'.
- Registro auditável com evento HR_IMPORT em formato JSON.
"""

import csv
import logging
import os
from datetime import datetime

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.governance.models import Cargo, Colaborador, Departamento, Localidade

logger = logging.getLogger("gatekeeper.audit")

COLUNAS_OBRIGATORIAS = {
    "matricula",
    "nome_completo",
    "email_corporativo",
    "departamento",
    "cargo",
    "localidade",
    "data_admissao",
}

LIMITE_TAMANHO_BYTES = 5 * 1024 * 1024  # 5MB


def sanitizar_celula_csv(valor):
    """Mitiga CSV Formula Injection neutralizando caracteres de início de fórmula."""
    if not valor:
        return ""
    val_str = str(valor).strip()
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        val_str = "'" + val_str
    return val_str


class Command(BaseCommand):
    help = "Importa cadastro de colaboradores a partir de arquivo CSV corporativo."

    def add_arguments(self, parser):
        parser.add_argument("csv_file", type=str, help="Caminho do arquivo CSV a ser importado.")
        parser.add_argument(
            "--aplicar",
            action="store_true",
            help="Grava as alterações no banco de dados. Sem esta flag, executa em modo simulação.",
        )
        parser.add_argument(
            "--simular",
            action="store_true",
            help="Modo simulação: valida e exibe o relatório sem persistir dados (padrão).",
        )

    def handle(self, *args, **options):
        caminho_csv = options["csv_file"]
        aplicar = options["aplicar"] and not options["simular"]

        if not os.path.exists(caminho_csv):
            raise CommandError(f"Arquivo CSV não encontrado: {caminho_csv}")

        tamanho = os.path.getsize(caminho_csv)
        if tamanho > LIMITE_TAMANHO_BYTES:
            raise CommandError(f"Arquivo CSV excede o limite de 5MB (tamanho: {tamanho} bytes).")

        self.stdout.write(f"[*] Processando arquivo: {caminho_csv} (Modo: {'APLICAR' if aplicar else 'SIMULAÇÃO'})")

        criados = 0
        atualizados = 0
        rejeitados = []
        matriculas_csv = set()
        emails_csv = set()

        try:
            with transaction.atomic():
                with open(caminho_csv, encoding="utf-8-sig") as f:
                    leitor = csv.DictReader(f, delimiter=";")
                    if not leitor.fieldnames:
                        raise CommandError("Arquivo CSV vazio ou sem cabeçalho válido.")

                    colunas_presentes = set(leitor.fieldnames)
                    if not COLUNAS_OBRIGATORIAS.issubset(colunas_presentes):
                        faltantes = COLUNAS_OBRIGATORIAS - colunas_presentes
                        raise CommandError(f"Colunas obrigatórias ausentes no CSV: {', '.join(faltantes)}")

                    for num_linha, linha in enumerate(leitor, start=2):
                        matricula = sanitizar_celula_csv(linha.get("matricula"))
                        nome_completo = sanitizar_celula_csv(linha.get("nome_completo"))
                        email_corp = sanitizar_celula_csv(linha.get("email_corporativo")).lower()
                        depto_str = sanitizar_celula_csv(linha.get("departamento"))
                        cargo_str = sanitizar_celula_csv(linha.get("cargo"))
                        loc_str = sanitizar_celula_csv(linha.get("localidade"))
                        data_adm_str = sanitizar_celula_csv(linha.get("data_admissao"))

                        if not matricula or not email_corp or not nome_completo:
                            rejeitados.append(
                                {"linha": num_linha, "erro": "Campos essenciais em branco (matrícula, e-mail ou nome)"}
                            )
                            continue

                        matriculas_csv.add(matricula)
                        emails_csv.add(email_corp)

                        # Validação / Resolução de Entidades
                        try:
                            data_adm = datetime.strptime(data_adm_str, "%Y-%m-%d").date()
                        except ValueError:
                            try:
                                data_adm = datetime.strptime(data_adm_str, "%d/%m/%Y").date()
                            except ValueError:
                                rejeitados.append(
                                    {
                                        "linha": num_linha,
                                        "erro": f"Data de admissão inválida: '{data_adm_str}' (esperado AAAA-MM-DD ou DD/MM/AAAA)",
                                    }
                                )
                                continue

                        depto, _ = Departamento.objects.get_or_create(
                            sigla=depto_str[:10].upper(), defaults={"nome": depto_str}
                        )
                        loc, _ = Localidade.objects.get_or_create(
                            codigo=loc_str[:20].upper(),
                            defaults={"nome": loc_str, "cidade": loc_str, "estado": "BR"},
                        )
                        cargo, _ = Cargo.objects.get_or_create(
                            nome=cargo_str, departamento=depto, defaults={"descricao": cargo_str}
                        )

                        colab = (
                            Colaborador.objects.filter(matricula=matricula).first()
                            or Colaborador.objects.filter(email_corporativo=email_corp).first()
                        )

                        if colab:
                            colab.nome_completo = nome_completo
                            colab.email_corporativo = email_corp
                            colab.departamento = depto
                            colab.cargo = cargo
                            colab.localidade = loc
                            colab.data_admissao = data_adm
                            acao = "atualizado"
                        else:
                            colab = Colaborador(
                                matricula=matricula,
                                nome_completo=nome_completo,
                                email_corporativo=email_corp,
                                departamento=depto,
                                cargo=cargo,
                                localidade=loc,
                                data_admissao=data_adm,
                                status=Colaborador.StatusColaborador.ATIVO,
                            )
                            acao = "criado"

                        try:
                            colab.full_clean()
                            if aplicar:
                                colab.save()
                            if acao == "criado":
                                criados += 1
                            else:
                                atualizados += 1
                        except ValidationError as e:
                            rejeitados.append(
                                {"linha": num_linha, "erro": str(e.message_dict if hasattr(e, "message_dict") else e)}
                            )

                # Colaboradores no banco não presentes no CSV -> Reportar 'a verificar' (NUNCA desliga automaticamente)
                ausentes = (
                    Colaborador.objects.filter(status=Colaborador.StatusColaborador.ATIVO)
                    .exclude(matricula__in=matriculas_csv)
                    .exclude(email_corporativo__in=emails_csv)
                )
                total_ausentes = ausentes.count()

                if not aplicar:
                    # Em modo simulação, aborta a transação para garantir que nada seja alterado
                    transaction.set_rollback(True)

        except Exception as e:
            if not isinstance(e, CommandError):
                raise CommandError(f"Falha durante a importação do CSV: {e}") from e
            raise

        logger.info(
            "HR_IMPORT",
            extra={
                "audit": {
                    "arquivo": os.path.basename(caminho_csv),
                    "modo": "APLICAR" if aplicar else "SIMULAR",
                    "criados": criados,
                    "atualizados": atualizados,
                    "rejeitados": len(rejeitados),
                    "colaboradores_a_verificar": total_ausentes,
                }
            },
        )

        self.stdout.write(
            self.style.SUCCESS(f"\n[+] Relatório de Importação ({'APLICADO' if aplicar else 'SIMULADO'}):")
        )
        self.stdout.write(f"    - Novos colaboradores: {criados}")
        self.stdout.write(f"    - Colaboradores atualizados: {atualizados}")
        self.stdout.write(f"    - Registros rejeitados com erro: {len(rejeitados)}")
        self.stdout.write(
            self.style.WARNING(f"    - Colaboradores ativos no sistema ausentes no CSV (A VERIFICAR): {total_ausentes}")
        )

        if rejeitados:
            self.stdout.write(self.style.ERROR("\nDetalhe dos erros encontrados:"))
            for r in rejeitados[:10]:
                self.stdout.write(f"    Linha {r['linha']}: {r['erro']}")
            if len(rejeitados) > 10:
                self.stdout.write(f"    ... e mais {len(rejeitados) - 10} erro(s).")
