-- 1. Activation de l'extension pour générer des UUIDs (IDs uniques)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Création des types énumérés (pour standardiser les statuts et sévérités)
CREATE TYPE scan_status AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED');
CREATE TYPE severity_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- ==========================================
-- TABLE 1 : SCANS (L'ordre de mission)
-- ==========================================
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_input VARCHAR(255) NOT NULL, -- ex: "192.168.1.0/24"
    status scan_status DEFAULT 'PENDING',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    scan_type VARCHAR(50) DEFAULT 'FULL' -- ex: "QUICK", "FULL", "WEB"
);

-- ==========================================
-- TABLE 2 : HOSTS (Les machines découvertes)
-- ==========================================
CREATE TABLE hosts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE, -- Si on supprime le scan, on supprime ses hôtes
    ip_address INET NOT NULL, -- Type spécial Postgres pour les IPs (gère IPv4/IPv6)
    hostname VARCHAR(255),
    os_family VARCHAR(100), -- ex: "Linux", "Windows"
    os_accuracy INT, -- Pourcentage de certitude Nmap
    is_up BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, ip_address) -- Évite les doublons d'IP dans un même scan
);

-- ==========================================
-- TABLE 3 : SERVICES (Les ports ouverts)
-- ==========================================
CREATE TABLE services (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE,
    port_number INT NOT NULL,
    protocol VARCHAR(10) DEFAULT 'tcp', -- tcp ou udp
    service_name VARCHAR(100), -- ex: ssh, http
    product VARCHAR(200), -- ex: OpenSSH
    version VARCHAR(100), -- ex: 8.2p1
    banner TEXT, -- La bannière brute récupérée
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, port_number, protocol)
);

-- ==========================================
-- TABLE 4 : VULNERABILITIES (Le rapport unifié)
-- ==========================================
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE,
    service_id UUID REFERENCES services(id) ON DELETE CASCADE, -- Peut être NULL si la faille touche l'OS entier
    tool_source VARCHAR(50) NOT NULL, -- ex: "Nmap", "OpenVAS", "Nikto"
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity severity_level DEFAULT 'INFO',
    cve_id VARCHAR(50), -- ex: CVE-2021-44228
    remediation TEXT, -- Conseil pour corriger
    raw_output TEXT, -- La preuve technique (output du script)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- TABLE 5 : CREDENTIALS (Le butin Hydra)
-- ==========================================
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_id UUID REFERENCES services(id) ON DELETE CASCADE,
    username VARCHAR(100) NOT NULL,
    password_enc TEXT NOT NULL, -- ATTENTION: Stocker chiffré (Fernet) comme demandé dans le CdC
    is_admin BOOLEAN DEFAULT FALSE,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index pour accélérer les recherches fréquentes
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_hosts_ip ON hosts(ip_address);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);