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
    ffuf \
    sqlmap \
    nikto \
    dirb \
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

# Setup OpenVAS
RUN apt install -y openvas \
    && greenbone-nvt-sync \
    && openvas-setup \
    && openvas-start \
    && openvas-client -u admin -w admin
    

# API
COPY app ./app

EXPOSE 8000

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]