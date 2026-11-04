# OpsAI variant B - server image (TZ FR-800..FR-804).
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY pyproject.toml README.md ./
COPY opsai ./opsai
RUN pip install --prefix=/install --no-warn-script-location . \
    && rm -rf /install/lib/python3.12/site-packages/pip*

FROM python:3.12-slim
LABEL org.opencontainers.image.title="OpsAI-A" \
      org.opencontainers.image.description="OpsAI variant B - log analysis assistant (server)" \
      org.opencontainers.image.source="https://github.com/RaviSileb/OpsAI-A"

ENV PYTHONUNBUFFERED=1 \
    OPSAI_MODE=server \
    OPSAI_HOST=0.0.0.0 \
    OPSAI_PORT=8080 \
    OPSAI_DATA_DIR=/data \
    PATH=/app/bin:$PATH

# Runtime needs no package installer: drop pip/setuptools/wheel to shrink
# the image and to silence scanner hits on pip's vendored copies.
RUN groupadd -r opsai --gid 10001 && useradd -r -g opsai --uid 10001 opsai \
    && mkdir -p /data /app && chown opsai:opsai /data /app \
    && apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/python3.12/site-packages/pip* \
    && rm -rf /usr/local/lib/python3.12/site-packages/setuptools* \
    && rm -rf /usr/local/lib/python3.12/site-packages/wheel* \
    && rm -f /usr/local/bin/pip*

COPY --from=builder /install /usr/local
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER 10001:10001
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/api/v1/health/live || exit 1
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["opsai", "server"]
