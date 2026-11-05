#!/usr/bin/env bash
# ==============================================================================
# GateKeeper-DBF - Script de Backup com Criptografia Assimétrica (age) (Fase 4.4 / 8.4)
# CIS Controls v8 (11.1 / 11.2 / 11.4) - Backups Criptografados com Chave Pública
# ==============================================================================
set -euo pipefail

# Diretório padrão para backups (preferencialmente fora da árvore da aplicação)
BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

# 1. Validação Fail-Closed da Chave Pública age
: "${BACKUP_AGE_RECIPIENT:?ERRO CRÍTICO: Defina a chave pública 'age' em BACKUP_AGE_RECIPIENT (ex: age1...)}"

# 2. Verificação de dependência do binário 'age'
if ! command -v age >/dev/null 2>&1; then
    echo "[-] ERRO CRÍTICO: Utilitário 'age' não encontrado no PATH." >&2
    echo "    Instale via gerenciador de pacotes (ex: 'apt install age' ou 'pacman -S age') ou baixe em https://github.com/FiloSottile/age" >&2
    exit 1
fi

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

FINAL_FILE="${BACKUP_DIR}/gatekeeper_${TIMESTAMP}.dump.age"
PARTIAL_FILE="${FINAL_FILE}.partial"
trap 'rm -f "${PARTIAL_FILE}"' EXIT

echo "[+] [$(date)] Iniciando rotina de backup criptografado do GateKeeper-DBF..."

# 3. Execução em Pipe sem arquivos intermediários em texto claro no disco
# As credenciais do Postgres NUNCA devem ser passadas via argumento de CLI (visíveis no ps).
# Falha-se explicitamente se DATABASE_URL estiver presente para mitigar vazamento de credenciais.
if [[ -n "${DATABASE_URL:-}" ]]; then
    echo "[-] ERRO DE SEGURANÇA: DATABASE_URL não deve ser utilizada diretamente no backup para evitar exposição de credenciais em processos (ps)." >&2
    echo "    Configure as variáveis padrão libpq (PGHOST, PGUSER, PGDATABASE, PGPORT) e utilize ~/.pgpass (permissão 600) ou PGPASSWORD." >&2
    exit 1
fi

if [[ -n "${PGDATABASE:-}" || -n "${PGHOST:-}" ]]; then
    echo "    • Modo: PostgreSQL (dump custom compactado em pipe com criptografia age via libpq/pgpass)"
    pg_dump --format=custom | age -r "${BACKUP_AGE_RECIPIENT}" > "${PARTIAL_FILE}"
elif [[ -f "db.sqlite3" ]]; then
    echo "    • Modo: SQLite (dump em pipe com criptografia age)"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 db.sqlite3 ".dump" | age -r "${BACKUP_AGE_RECIPIENT}" > "${PARTIAL_FILE}"
    else
        cat db.sqlite3 | age -r "${BACKUP_AGE_RECIPIENT}" > "${PARTIAL_FILE}"
    fi
else
    echo "[-] ERRO: Nenhuma base de dados encontrada para backup." >&2
    exit 1
fi

# Move atomicamente o arquivo temporário apenas após sucesso completo do pipe
mv "${PARTIAL_FILE}" "${FINAL_FILE}"

# 4. Permissões estritas no arquivo gerado (apenas leitura do dono)
chmod 600 "${FINAL_FILE}"
echo "[+] [$(date)] Backup concluído com sucesso e protegido por criptografia de chave pública:"
echo "    📄 Arquivo: ${FINAL_FILE}"
echo "    🔐 Recipient: ${BACKUP_AGE_RECIPIENT}"
echo ""
echo "    ℹ️  Instrução para Restauração (SOC / DR Procedure):"
echo "        age -d -i /caminho/chave_privada_offline.key < '${FINAL_FILE}' | pg_restore -d \$DATABASE_URL"

# 5. Rotação automática de backups antigos
echo "[+] Purgando backups com mais de ${RETENTION_DAYS} dias..."
find "${BACKUP_DIR}" -type f -name "*.dump.age" -mtime "+${RETENTION_DAYS}" -delete
echo "[+] Rotina finalizada com sucesso."
