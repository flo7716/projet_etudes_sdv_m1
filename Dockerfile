FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Security tooling + Python runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    hydra \
    gobuster \
    dirbuster \
    ffuf \
    sqlmap \
    nikto \
    texlive-latex-recommended \
    texlive-latex-extra \
    texlive-fonts-recommended \
    curl \
    git \
    nuclei \
    aircrack-ng \
    metasploit-framework \
    john \
    wordlists \
    seclists \
    exploitdb \
    sslyze \
    tshark \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dézippage de rockyou.txt.gz
RUN gunzip -k /usr/share/wordlists/rockyou.txt.gz

# Installation des templates Nuclei
RUN git clone https://github.com/projectdiscovery/nuclei-templates.git /root/.local/nuclei-templates
RUN nuclei -update-templates

# Mise à jour de ClamAV
RUN freshclam

# Backend
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

# API
COPY app ./app

CMD ["python3", "-m", "app.main"]