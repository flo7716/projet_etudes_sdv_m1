FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    git \
    wget \
    nikto \
    gobuster \
    seclists \
    && rm -rf /var/lib/apt/lists/*

# wordlist
RUN mkdir /wordlists \
    && wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O /wordlists/rockyou.txt

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]