#!/usr/bin/env bash
# ==============================================================================
# GateKeeper-DBF - Build reprodutível do CSS (Tailwind standalone, sem Node)
#
# Compila static/css/input.css -> static/css/tailwind.min.css.
# O binário do Tailwind é baixado numa versão fixa e verificado por SHA-256
# (checksums oficiais do release) antes de ser executado.
#
# Uso:
#   scripts/build_css.sh            # compila
#   scripts/build_css.sh --check    # falha se o CSS commitado estiver desatualizado
# ==============================================================================
set -euo pipefail

TAILWIND_VERSION="3.4.17"
BIN_DIR=".django_tailwind_cli"
BIN="${BIN_DIR}/tailwindcss"
INPUT="static/css/input.css"
OUTPUT="static/css/tailwind.min.css"

cd "$(dirname "$0")/.."

# Checksums oficiais: https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/sha256sums.txt
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  ASSET="tailwindcss-linux-x64";   SHA256="7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4" ;;
    Linux-aarch64) ASSET="tailwindcss-linux-arm64"; SHA256="69b1378b8133192d7d2feb12a116fa12d035594f58db3eff215879e4ad8cf39b" ;;
    Darwin-x86_64) ASSET="tailwindcss-macos-x64";   SHA256="6cbdad74be776c087ffa5e9a057512c54898f9fe8828d3362212dfe32fc933a3" ;;
    Darwin-arm64)  ASSET="tailwindcss-macos-arm64"; SHA256="a1d0c7985759accca0bf12e51ac1dcbf0f6cf2fffb62e6e0f62d091c477a10a3" ;;
    *) echo "[-] Plataforma não suportada: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# 1. Garante o binário na versão exata e íntegro (baixa se faltar ou não conferir)
if [[ ! -x "${BIN}" || "$(sha256_of "${BIN}")" != "${SHA256}" ]]; then
    echo "[+] Baixando Tailwind v${TAILWIND_VERSION} (${ASSET})..."
    mkdir -p "${BIN_DIR}"
    TMP="$(mktemp "${BIN_DIR}/tailwindcss.XXXXXX")"
    trap 'rm -f "${TMP}"' EXIT
    curl -fsSL --max-time 120 -o "${TMP}" \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/${ASSET}"
    if [[ "$(sha256_of "${TMP}")" != "${SHA256}" ]]; then
        echo "[-] ERRO: checksum SHA-256 do binário não confere. Abortando." >&2
        exit 1
    fi
    chmod +x "${TMP}"
    mv "${TMP}" "${BIN}"
    trap - EXIT
fi

# 2. Compila
if [[ "${1:-}" == "--check" ]]; then
    TMP_OUT="$(mktemp)"
    trap 'rm -f "${TMP_OUT}"' EXIT
    "${BIN}" -c tailwind.config.js -i "${INPUT}" -o "${TMP_OUT}" --minify 2>/dev/null
    if ! cmp -s "${TMP_OUT}" "${OUTPUT}"; then
        echo "[-] ${OUTPUT} está desatualizado em relação aos templates/input.css." >&2
        echo "    Rode: scripts/build_css.sh  e faça commit do resultado." >&2
        exit 1
    fi
    echo "[+] ${OUTPUT} está atualizado."
else
    "${BIN}" -c tailwind.config.js -i "${INPUT}" -o "${OUTPUT}" --minify
    echo "[+] CSS compilado em ${OUTPUT}"
fi
