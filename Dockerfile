# syntax=docker/dockerfile:1.7
# Imagen única para todos los roles (ingest / worker / api / all).

FROM python:3.12-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install .

FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.title="Centinela" \
      org.opencontainers.image.description="Análisis pasivo de correo para PyMEs: RATs, stealers y phishing" \
      org.opencontainers.image.licenses="Apache-2.0"

# unar: extracción de .rar (rarfile lo usa como backend). tini: PID 1 que propaga señales.
RUN apt-get update \
 && apt-get install -y --no-install-recommends unar tini ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 centinela \
 && useradd --system --uid 10001 --gid centinela --home-dir /data --shell /usr/sbin/nologin centinela \
 && mkdir -p /data /app/rules \
 && chown centinela:centinela /data

COPY --from=build /opt/venv /opt/venv
COPY rules /app/rules
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CENTINELA_CONFIG=/config/config.yaml
WORKDIR /app
USER centinela
VOLUME ["/data"]
EXPOSE 8080 8899 2525

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import os,sys,urllib.request; r=os.environ.get('CENTINELA_ROLE','all'); sys.exit(0) if r in ('ingest','worker') else urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"

ENTRYPOINT ["/usr/bin/tini", "--", "centinela"]
CMD ["run", "--role", "all"]
