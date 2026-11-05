# ==============================================================================
# GateKeeper-DBF - Dockerfile Multi-Stage de Alta Segurança (Fase 4.4)
# CIS Docker Benchmark / OWASP Container Security / Non-Root Execution
# ==============================================================================

# ------------------------------------------------------------------------------
# Estágio 1: Builder (Compilação e Resolução Criptográfica de Dependências)
# ------------------------------------------------------------------------------
FROM python:3.14-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Dependências de sistema necessárias para compilação (gcc, bibliotecas de build)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Compila os wheels estritamente validados contra os hashes SHA-256 do requirements.txt
RUN pip wheel --no-deps --require-hashes -r requirements.txt -w /build/wheels

# ------------------------------------------------------------------------------
# Estágio 2: Runtime Seguro (Mínima Superfície de Ataque e Usuário Não-Root)
# ------------------------------------------------------------------------------
FROM python:3.14-slim AS runtime

LABEL maintainer="David B. F. <davidbraferti@gmail.com>" \
      security.standards="CIS Docker Benchmark / NIST SP 800-190" \
      app.name="GateKeeper-DBF"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Criação de usuário e grupo de sistema desprivilegiado (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

# Bibliotecas de runtime estritamente necessárias (libpq5 para PostgreSQL, curl para healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalação dos pacotes a partir dos wheels gerados no estágio anterior
COPY --from=builder /build/wheels /wheels
COPY requirements.txt .
RUN pip install --no-index --find-links=/wheels -r requirements.txt && rm -rf /wheels

# Cópia do código-fonte da aplicação
COPY --chown=appuser:appgroup . .

# Coleta de arquivos estáticos com cache busting e compressão WhiteNoise
RUN DJANGO_SETTINGS_MODULE=core.settings \
    SECRET_KEY=dummy-build-key-for-collectstatic-only \
    DEBUG=False \
    python manage.py collectstatic --noinput

# Ajuste estrito de permissões de diretórios
RUN chown -R appuser:appgroup /app

# Transição para usuário desprivilegiado (Defense-in-Depth)
USER 10001:10001

EXPOSE 8000

# Healthcheck nativo (Fase 9.2): /healthz/ verifica o banco e não depende de ALLOWED_HOSTS nem de HTTPS
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz/ || exit 1

# Execução em produção via Gunicorn com timeout e logs estruturados
CMD ["gunicorn", "core.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
