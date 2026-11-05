#!/usr/bin/env bash
# ==============================================================================
# GateKeeper-DBF - Script de Backup Criptografado de Banco de Dados (Fase 4.4)
# CIS Controls v8 (11.1 / 11.2) - Backups Periódicos & Criptografia em Repouso
# ==============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

echo "[+] [$(date)] Iniciando rotina de backup do GateKeeper-DBF..."

# 1. Determina o mecanismo de backup (PostgreSQL vs SQLite)
if [[ -n "${DATABASE_URL:-}" && "${DATABASE_URL}" == postgres* ]]; then
    RAW_BACKUP="${BACKUP_DIR}/dump_pg_${TIMESTAMP}.sql.gz"
    echo "    • Modo: PostgreSQL"
    pg_dump "${DATABASE_URL}" | gzip -9 > "${RAW_BACKUP}"
else
    RAW_BACKUP="${BACKUP_DIR}/dump_sqlite_${TIMESTAMP}.sqlite3.gz"
    echo "    • Modo: SQLite (Local)"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 db.sqlite3 ".backup '${BACKUP_DIR}/temp_${TIMESTAMP}.sqlite3'"
        gzip -9 "${BACKUP_DIR}/temp_${TIMESTAMP}.sqlite3"
        mv "${BACKUP_DIR}/temp_${TIMESTAMP}.sqlite3.gz" "${RAW_BACKUP}"
    else
        gzip -c db.sqlite3 > "${RAW_BACKUP}"
    fi
fi

# 2. Criptografia AES-256-CBC com PBKDF2 (se chave for fornecida)
if [[ -n "${ENCRYPTION_KEY}" ]]; then
    ENCRYPTED_BACKUP="${RAW_BACKUP}.enc"
    echo "    • Criptografando com AES-256-CBC..."
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -in "${RAW_BACKUP}" \
        -out "${ENCRYPTED_BACKUP}" \
        -pass "pass:${ENCRYPTION_KEY}"
    rm -f "${RAW_BACKUP}"
    FINAL_FILE="${ENCRYPTED_BACKUP}"
else
    echo "    ⚠️ AVISO: BACKUP_ENCRYPTION_KEY não definida. O arquivo permanecerá compactado sem criptografia adicional."
    FINAL_FILE="${RAW_BACKUP}"
fi

# 3. Permissões estritas no arquivo gerado
chmod 600 "${FINAL_FILE}"
echo "[+] [$(date)] Backup concluído com sucesso: ${FINAL_FILE}"

# 4. Rotação automática de backups antigos
echo "[+] Purgando backups com mais de ${RETENTION_DAYS} dias..."
find "${BACKUP_DIR}" -type f \( -name "*.gz" -o -name "*.enc" \) -mtime "+${RETENTION_DAYS}" -delete
echo "[+] Rotina finalizada."

