FROM --platform=linux/amd64 python:3.13-slim@sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /workspace

# Create an unprivileged runtime identity.
RUN groupadd --gid 10001 fyp \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin fyp

COPY pyproject.toml README.md ./
COPY requirements/isolated-py313-linux-amd64.lock ./requirements/
COPY agents ./agents
COPY orchestrator ./orchestrator
COPY schemas ./schemas
COPY services ./services
COPY llm ./llm
COPY dummy_apps ./dummy_apps
COPY infrastructure ./infrastructure
COPY security_tests ./security_tests
COPY verification ./verification
COPY config ./config

# Dependency installation occurs while building the trusted image.
# Runtime security-test containers are isolated by Compose networking.
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes \
        --index-url https://pypi.org/simple \
        -r requirements/isolated-py313-linux-amd64.lock \
    && python -m pip install --no-cache-dir --no-deps --no-build-isolation . \
    && mkdir -p /runtime \
    && chown -R 10001:10001 /runtime

USER 10001:10001

CMD ["sh", "-c", "python -m dummy_apps.vulnerable_store.app.reset && exec uvicorn dummy_apps.vulnerable_store.app.main:app --host 0.0.0.0 --port 8000"]
