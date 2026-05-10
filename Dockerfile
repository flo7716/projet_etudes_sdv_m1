FROM kalilinux/kali-rolling

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

# Mise à jour
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    hydra \
    john \
    gobuster \
    ffuf \
    sqlmap \
    nikto \
    whatweb \
    seclists \
    metasploit-framework \
    curl \
    git \
    wget

# FastAPI
RUN pip3 install fastapi uvicorn python-multipart

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]