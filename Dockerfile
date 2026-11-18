FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY --from=ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
# The source files can be 0600 on a developer machine and the runtime user is not root. A RUN step instead of
# COPY --chmod, because the legacy builder of the server's docker.io package does not know that option.
COPY app ./app
COPY runner ./runner
RUN chmod -R a+rX /app/app /app/runner && chmod a+r /app/pyproject.toml

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ARG SERVICE_VERSION=dev
# git and osv-scanner for the nightly OSV scan of the repositories (app/security/osv.py).
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0 /osv-scanner /usr/local/bin/osv-scanner
ENV SERVICE_VERSION=${SERVICE_VERSION} PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
LABEL org.opencontainers.image.revision=${SERVICE_VERSION}
WORKDIR /app
COPY --from=build /app /app
# The service runs with a read-only root file system in production (deploy/ops-server/compose.yml). The OSV scan
# clones and scans below this directory; compose mounts a volume there, which starts out with this owner.
RUN useradd -r -u 10001 ops && install -d -o 10001 -g 10001 -m 700 /var/lib/pikett/work
USER 10001
EXPOSE 8030
HEALTHCHECK CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8030/health')"
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8030"]
