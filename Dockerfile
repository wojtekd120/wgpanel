FROM node:22-bookworm-slim AS frontend-build
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app/backend \
    WGPANEL_IN_DOCKER=true \
    WGPANEL_DATABASE_PATH=/var/lib/wgpanel/wgpanel.db \
    WGPANEL_WG_CONFIG_PATH=/etc/wireguard/wg0.conf \
    WGPANEL_HELPER_PATH=/usr/local/sbin/wgpanel-helper \
    WGPANEL_RUN_DIR=/run/wgpanel

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        libcap2-bin \
        sudo \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system wgpanel \
    && adduser --system --ingroup wgpanel --home /var/lib/wgpanel wgpanel \
    && python -m venv /opt/venv

WORKDIR /app/backend
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend/app /app/backend/app
COPY backend/scripts /app/backend/scripts
COPY helper/wgpanel-helper /usr/local/sbin/wgpanel-helper
COPY backend/apply_sudoers.example /etc/sudoers.d/wgpanel
COPY --from=frontend-build /src/frontend/dist /app/frontend/dist
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod 0750 /usr/local/sbin/wgpanel-helper \
    && chown root:root /usr/local/sbin/wgpanel-helper \
    && setcap cap_net_admin+ep /usr/bin/wg \
    && chmod 0440 /etc/sudoers.d/wgpanel \
    && visudo -cf /etc/sudoers.d/wgpanel \
    && chmod 0755 /usr/local/bin/docker-entrypoint.sh \
    && chmod 0755 /app/backend/scripts/wgpanel_admin.py \
    && ln -s /app/backend/scripts/wgpanel_admin.py /usr/local/bin/wgpanel-admin \
    && mkdir -p /var/lib/wgpanel /run/wgpanel \
    && chown -R wgpanel:wgpanel /var/lib/wgpanel /run/wgpanel /app

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${WGPANEL_PORT:-8080}/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
