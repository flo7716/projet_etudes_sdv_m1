FROM python:3.11-slim

WORKDIR /app

# Installer outils + git
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    git \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ========================
# INSTALL SECLISTS
# ========================
RUN git clone https://github.com/danielmiessler/SecLists.git /wordlists/SecLists

# ========================
# ROCKYOU (souvent compressé)
# ========================
# rockyou
RUN wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O /wordlists/rockyou.txt

# ========================
# POETRY
# ========================
RUN pip install poetry

COPY pyproject.toml poetry.lock ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-root

COPY . .

CMD ["celery", "-A", "toolbox.workers.celery_app", "worker", "--loglevel=info"]