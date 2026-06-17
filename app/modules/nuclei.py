import shlex
import subprocess

from app.modules.interactive import prompt_text


def parse_nuclei(output_file: str):
    import os
    if not os.path.exists(output_file):
        return {"tool": "nuclei", "findings": [], "severity": "low", "raw_output": ""}

    with open(output_file, "r") as f:
        output = f.read()

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    
    # Échelle d'évaluation pour garder uniquement le maximum trouvé
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_severity = "low"
    
    for line in lines:
        findings.append(line)
        line_lower = line.lower()
        
        # Détection dynamique de l'étiquette [low], [medium], [high], [critical] dans le message
        for level in ["info", "low", "medium", "high", "critical"]:
            if f"[{level}]" in line_lower:
                if severity_order[level] > severity_order[max_severity]:
                    max_severity = level

    # On mappe "info" vers "low" pour la cohérence des graphiques et tableaux
    if max_severity == "info":
        max_severity = "low"

    return {
        "tool": "nuclei",
        "lines_count": len(lines),
        "findings": findings[:25],
        "raw_output": output[:4000],
        "severity": max_severity,
    }


def run_nuclei(target: str, options: str = ""):
    command = ["nuclei", "-target", target, "-o", "nuclei_$(date +%Y%m%d_%H%M%S).txt"]

    if options:
        command.extend(shlex.split(options))

    result = subprocess.run(command, capture_output=True, text=True)
    output = "\n".join(filter(None, [result.stdout, result.stderr]))

    if result.returncode != 0:
        return {
            "tool": "nuclei",
            "command": " ".join(command),
            "error": output or "nuclei scan failed.",
        }

    return parse_nuclei("nuclei_$(date +%Y%m%d_%H%M%S).txt")


def run_nuclei_interactive():
    target = prompt_text(
        "Enter target URL or host:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional nuclei options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning nuclei on {target}...")
    return run_nuclei(target, options)