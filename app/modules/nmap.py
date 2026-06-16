# app/modules/nmap.py
import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text


def parse_nmap(xml_output):
    root = ET.fromstring(xml_output)
    host = root.find("host")

    addresses = []
    hostnames = []
    status = None
    if host is not None:
        status_el = host.find("status")
        if status_el is not None:
            status = status_el.get("state")

        for address in host.findall("address"):
            addr = address.get("addr")
            if addr:
                addresses.append(addr)

        for hostname in host.findall("hostname"):
            name = hostname.get("name")
            if name:
                hostnames.append(name)

    scan_info = {}
    scan_info_el = root.find("scaninfo")
    if scan_info_el is not None:
        scan_info = scan_info_el.attrib

    os_matches = []
    for osmatch in root.findall(".//osmatch"):
        os_matches.append({
            "name": osmatch.get("name"),
            "accuracy": osmatch.get("accuracy"),
            "line": osmatch.get("line"),
        })

    ports = []
    for port in root.findall(".//port"):
        state_el = port.find("state")
        if state_el is None:
            continue

        state = state_el.get("state")
        service_el = port.find("service")
        service = {}
        if service_el is not None:
            service = {
                "name": service_el.get("name"),
                "product": service_el.get("product"),
                "version": service_el.get("version"),
                "extrainfo": service_el.get("extrainfo"),
            }

        scripts = []
        for script in port.findall("script"):
            scripts.append({
                "id": script.get("id"),
                "output": script.get("output"),
            })

        ports.append({
            "port": port.get("portid"),
            "protocol": port.get("protocol"),
            "state": state,
            "service": service,
            "scripts": scripts,
        })

    open_ports = [p for p in ports if p["state"] == "open"]

    scan_stats = {}
    finished = root.find("runstats/finished")
    if finished is not None:
        scan_stats = finished.attrib

    # =========================================================
    # ANALYSE DYNAMIQUE DES PARAMÈTRES POUR GENERER LES FINDINGS
    # =========================================================
    findings = []
    max_weight = 1  # 1: low, 2: medium, 3: high, 4: critical
    
    # Dictionnaire de correspondance poids -> chaînes pour le rapport
    severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}

    for p in open_ports:
        port_num = int(p["port"])
        service_name = (p["service"].get("name") or "").lower()
        product = (p["service"].get("product") or "").lower()
        
        # Règle par défaut pour chaque port identifié ouvert
        findings.append(f"Port {port_num} ({service_name or 'unknown'}) is open.")

        # Analyse heuristique des protocoles obsolètes ou sensibles
        if port_num == 21 or "ftp" in service_name:
            # Vérification de l'accès FTP anonyme si le script de Nmap a été exécuté
            anon_login = any("ftp-anon" in s["id"] for s in p["scripts"])
            if anon_login:
                findings.append(f"Critical Vulnerability: Anonymous FTP login is allowed on port {port_num}.")
                max_weight = max(max_weight, 4)
            else:
                findings.append(f"Risk: Cleartext FTP service active on port {port_num}.")
                max_weight = max(max_weight, 2)

        elif port_num == 23 or "telnet" in service_name:
            findings.append(f"High Vulnerability: Obsolete cleartext Telnet management protocol detected on port {port_num}.")
            max_weight = max(max_weight, 3)

        elif port_num == 445 or "microsoft-ds" in service_name or "smb" in service_name:
            # Détection de la présence de protocoles SMB à risques (comme SMBv1 vulnérable à EternalBlue)
            findings.append(f"Risk: Exposed SMB (Server Message Block) service active on port {port_num}.")
            max_weight = max(max_weight, 2)
            # Si le script de détection d'OS remonte un système obsolète (ex: Windows XP / 2003 / 7)
            if any(any(x in m["name"].lower() for x in ["xp", "2003", "windows 7"]) for m in os_matches):
                findings.append("Critical Vulnerability: Legacy SMB services active on an obsolete Operating System.")
                max_weight = max(max_weight, 4)

        elif port_num == 3389 or "ms-wbt-server" in service_name:
            findings.append(f"Risk: Remote Desktop Protocol (RDP) interface exposed on port {port_num}.")
            max_weight = max(max_weight, 2)

        # Exposition d'interfaces de gestion de bases de données relationnelles
        elif port_num in [3306, 5432, 1433, 1521] or any(x in service_name for x in ["mysql", "postgresql", "ms-sql", "oracle"]):
            findings.append(f"High Risk: Database engine management port ({port_num} - {service_name}) directly exposed.")
            max_weight = max(max_weight, 3)

    # Résumé général adapté au résultat global
    if max_weight == 4:
        summary = f"Nmap discovered critical exposure on open ports ({len(open_ports)} ports active)."
    elif max_weight == 3:
        summary = f"Nmap discovered high risk service configurations during port scanning."
    else:
        summary = f"Nmap completed successfully. Identified {len(open_ports)} active services."

    return {
        "status": status,
        "host": {
            "addresses": addresses,
            "hostnames": hostnames,
        },
        "scan_info": scan_info,
        "scan_stats": scan_stats,
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
        "os_matches": os_matches,
        # Clés requises par l'orchestrateur de reporting
        "findings": findings,
        "severity": severity_map[max_weight],
        "summary": summary
    }


def run_nmap(target, options=""):
    # Arguments de base appliqués par défaut si non écrasés
    command = [
        "nmap",
        "-sV",
        "-sC",
        "-O",
        "-oX", "-"  # Sortie au format XML sur le flux standard stdout pour traitement par l'ElementTree
    ]

    if options:
        import shlex
        command.extend(shlex.split(options))

    # Ajout automatique de la cible à la fin de la commande
    command.append(target)

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return {
            "error": result.stderr,
            "findings": [f"Error during network scanning execution: {result.stderr[:100]}"],
            "severity": "low",
            "summary": "Nmap failed to execute properly."
        }

    try:
        return parse_nmap(result.stdout)

    except ET.ParseError:
        return {
            "error": "Impossible de parser le XML Nmap",
            "raw_output": result.stdout[:500],
            "findings": ["Error parsing Nmap standard XML structure."],
            "severity": "low",
            "summary": "XML structural anomaly discovered."
        }


def run_nmap_interactive():
    target = prompt_text(
        "Enter target host/IP:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional nmap options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning nmap scan on {target}...")
    return run_nmap(target, options)