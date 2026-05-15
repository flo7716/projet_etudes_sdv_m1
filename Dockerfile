FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Outils système + Python + Node.js
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    hydra \
    gobuster \
    dirb \
    dirbuster \
    ffuf \
    sqlmap \
    nikto \
    texlive-latex-recommended \
    texlive-latex-extra \
    texlive-fonts-recommended \
    curl \
    git \
    nodejs \
    npm \
    john \
    wordlists \
    seclists \
    && apt clean

WORKDIR /app

# Backend
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

# API
COPY app ./app

CMD ["python3", "-m", "app.main"]