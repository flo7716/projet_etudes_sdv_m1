# app/modules/nuclei.py
import os
import re
import shlex
import subprocess
from datetime import datetime

from app.modules.interactive import prompt_text


def parse_nuclei(output_file: str):
    if not os.path.exists(output_file):
        return {
            "tool": "nuclei",
            "lines_count": 0,
            "findings": [],
            "raw_output": "",
            "severity": "low",
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
            # Fallback
            line_lower = line.lower()
            for level in ["info", "low", "medium", "high", "critical"]:
                if f"[{level}]" in line_lower:
                    line_severity = level
                    if severity_order[level] > severity_order[max_severity]:
                        max_severity = level

        # On ajoute le label textuel pour faciliter le travail du renderer et de Matplotlib
        sev_label = line_severity.upper() if line_severity != "info" else "LOW"
        findings.append(f"{line} -> Severity: {sev_label}")

    if max_severity == "info":
        max_severity = "low"

    return {
        "tool": "nuclei",
        "lines_count": len(findings),
        "findings": findings[:25],  # Liste propre pour le tableau LaTeX
        "raw_output": output[:4000],
        "severity": max_severity,
    }


def run_nuclei(target: str, options: str = ""):
    # Génération d'un nom de fichier unique et horodaté (ex: nuclei_20260618_193000.txt)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"nuclei_{timestamp}.txt"
    
    command = ["nuclei", "-target", target, "-o", output_filename]

    if options:
        command.extend(shlex.split(options))

    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    output = "\n".join(filter(None, [result.stdout, result.stderr]))

    if result.returncode != 0 and not os.path.exists(output_filename):
        return {
            "tool": "nuclei",
            "command": " ".join(command),
            "error": output or "nuclei scan failed.",
            "findings": [],
            "severity": "low",
            "raw_output": output
        }

    # Analyse du fichier généré
    report_data = parse_nuclei(output_filename)
    
    # CRUCIAL : On NE supprime PAS le fichier texte pour que tools_renderer.py et charts.py 
    # puissent aller le lire et se synchroniser de façon autonome !
    
    return report_data


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