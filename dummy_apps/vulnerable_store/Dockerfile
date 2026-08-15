FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /workspace

# Create an unprivileged runtime identity.
RUN groupadd --gid 10001 fyp \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin fyp

COPY pyproject.toml README.md ./
COPY orchestrator ./orchestrator
COPY schemas ./schemas
COPY services ./services
COPY llm ./llm
COPY dummy_apps ./dummy_apps
COPY infrastructure ./infrastructure
COPY security_tests ./security_tests
COPY config ./config

# Dependency installation occurs while building the trusted image.
# Runtime security-test containers are isolated by Compose networking.
RUN python -m pip install --no-cache-dir . \
    && mkdir -p /runtime \
    && chown -R 10001:10001 /runtime

USER 10001:10001

CMD ["sh", "-c", "python -m dummy_apps.vulnerable_store.app.reset && exec uvicorn dummy_apps.vulnerable_store.app.main:app --host 0.0.0.0 --port 8000"]
