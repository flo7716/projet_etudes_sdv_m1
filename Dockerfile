FROM kalilinux/kali-rolling

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

# Outils pentest + Python
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    hydra \
    john \
    gobuster \
    seclists \
    ffuf \
    sqlmap \
    nikto \
    whatweb \
    seclists \
    metasploit-framework \
    curl \
    git \
    wget

# Créer environnement virtuel
RUN python3 -m venv /opt/venv

# Ajouter venv au PATH
ENV PATH="/opt/venv/bin:$PATH"

# Installer FastAPI dans le venv
RUN pip install --upgrade pip
RUN pip install fastapi uvicorn python-multipart

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]