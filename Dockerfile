FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --home-dir /app app

COPY pyproject.toml ./
COPY src ./src
COPY alembic.ini ./
COPY migrations ./migrations
COPY tests ./tests

ARG INSTALL_DEV=false
RUN if [ "$INSTALL_DEV" = "true" ]; then \
      pip install --no-cache-dir ".[dev]"; \
    else \
      pip install --no-cache-dir .; \
    fi

RUN chown -R app:app /app

USER app

EXPOSE 8000

CMD ["uvicorn", "vpn_service.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
