FROM python:3.11-slim

WORKDIR /app

# Installer dépendances système
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    netcat-openbsd \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Installer poetry
RUN pip install poetry

COPY pyproject.toml poetry.lock ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-root

COPY . .

CMD ["celery", "-A", "toolbox.workers.celery_app", "worker", "--loglevel=info"]
