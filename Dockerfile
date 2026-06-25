FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Security tooling + Python runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    # --- RUNTIME CORE & SYSTEM ---
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    git \
    # --- RECONNAISSANCE & SCANNING ---
    nmap \
    sslyze \
    tshark \
    # --- FUZZING & ENUMERATION ---
    gobuster \
    ffuf \
    nikto \
    # --- EXPLOITATION & BRUTE-FORCE ---
    sqlmap \
    nuclei \
    hydra \
    john \
    metasploit-framework \
    # --- WIRELESS TESTING ---
    aircrack-ng \
    # --- WORDLISTS & VULN DATABASES ---
    wordlists \
    seclists \
    exploitdb \
    # --- FORENSICS & MALWARE SCAN ---
    clamav \
    clamav-daemon \
    clamav-freshclam \
    # --- PDF RENDERING (LATEX) ---
    texlive-latex-recommended \
    texlive-latex-extra \
    texlive-fonts-recommended \
    # --- CACHE CLEANUP ---
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Unzip rockyou.txt.gz
RUN gunzip -k /usr/share/wordlists/rockyou.txt.gz

# Install Nuclei templates
RUN git clone https://github.com/projectdiscovery/nuclei-templates.git /root/.local/nuclei-templates
RUN nuclei -update-templates

# Clamscan database update
RUN freshclam

# Backend
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

# API
COPY app ./app

CMD ["python3", "-m", "app.main"]