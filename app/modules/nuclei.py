# app/modules/nuclei.py
import os
import re
import shlex
import subprocess
import tempfile
from datetime import datetime

from app.modules.interactive import prompt_text


def parse_nuclei(output_file: str):
    if not os.path.exists(output_file):
        return {
            "tool": "nuclei",
            "findings": [],
            "raw_output": "",
            "severity": "low",
            "summary": "Identified 0 alert exposures."
        }

    with open(output_file, "r", encoding="utf-8", errors="replace") as f:
        output = f.read()

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_severity = "info"
    
    # REGEX : Capture le contenu du 3ème crochet [template] [protocol] [SEVERITY]
    nuclei_pattern = re.compile(r"^\[[^\]]+\]\s+\[[^\]]+\]\s+\[([^\]]+)\]")

    for line in lines:
        # Ignorer les lignes de logs/bannières de Nuclei qui commencent par [INF] ou [WRN]
        if line.startswith(("[INF]", "[WRN]", "[ERR]")):
            continue
            
        match = nuclei_pattern.match(line)
        line_severity = "info"
        
        if match:
            line_severity = match.group(1).lower().strip()
            if line_severity in severity_order:
                if severity_order[line_severity] > severity_order[max_severity]:
                    max_severity = line_severity
        else:
            # Fallback si format de ligne exotique
            line_lower = line.lower()
            for level in ["info", "low", "medium", "high", "critical"]:
                if f"[{level}]" in line_lower:
                    line_severity = level
                    if severity_order[level] > severity_order[max_severity]:
                        max_severity = level

        # On garde l'alerte propre pour le Focus Technique détaillé et l'Annexe
        findings.append(line)

    if max_severity == "info":
        max_severity = "low"

    # FORMATAGE QUANTITATIF UNIFIÉ POUR LA MATRICE
    return {
        "tool": "nuclei",
        "findings": findings,  # Liste complète conservée pour les détails techniques plus loin
        "raw_output": output,
        "severity": max_severity,
        # Cette ligne permet à tools_renderer d'accoler automatiquement le nombre et la conséquence
        "summary": f"Identified {len(findings)} alert exposures."
    }


def run_nuclei(target: str, options: str = ""):
    # Utilisation du répertoire /tmp sécurisé pour éviter d'avoir des fichiers parasites partout
    fd, temp_output_path = tempfile.mkstemp(suffix=".txt", prefix="nuclei_")
    os.close(fd)
    
    command = ["nuclei", "-target", target, "-o", temp_output_path]

    if options:
        command.extend(shlex.split(options))

    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        fallback_output = "\n".join(filter(None, [result.stdout, result.stderr]))

        if result.returncode != 0 and (not os.path.exists(temp_output_path) or os.path.getsize(temp_output_path) == 0):
            return {
                "tool": "nuclei",
                "command": " ".join(command),
                "error": fallback_output or "nuclei scan failed.",
                "findings": [],
                "severity": "low",
                "raw_output": fallback_output,
                "summary": "Identified 0 alert exposures due to core engine runtime failure."
            }

        return parse_nuclei(temp_output_path)

    finally:
        # Destruction propre du fichier temporaire du conteneur après extraction
        if os.path.exists(temp_output_path):
            os.remove(temp_output_path)


def run_nuclei_interactive():
    target = prompt_text(
        "Enter target host/URL (e.g. http://172.18.0.2):",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional nuclei options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning nuclei on {target}...")
    return run_nuclei(target, options)