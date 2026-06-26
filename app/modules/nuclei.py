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
    
    # REGEX: Captures severity level from Nuclei output lines e.g. [info], [low], [medium]
    nuclei_pattern = re.compile(r"^\[[^\]]+\]\s+\[[^\]]+\]\s+\[([^\]]+)\]")

    for line in lines:
        if line.startswith(("[INF]", "[WRN]", "[ERR]")):
            continue
            
        match = nuclei_pattern.match(line)
        line_severity = "info"
        
        if match:
            line_severity = match.group(1).lower()
            if line_severity in severity_order and severity_order[line_severity] > severity_order[max_severity]:
                max_severity = line_severity
                
        findings.append(f"[{line_severity.upper()}] {line}")

    return {
        "tool": "nuclei",
        "findings": findings,
        "raw_output": output,
        "severity": max_severity,
        "summary": f"Identified {len(findings)} technical security alert vulnerabilities."
    }

def run_nuclei(target: str, options: str = ""):
    # Use temporary file pointer handling strategy for runtime containment
    fd, temp_output_path = tempfile.mkstemp(suffix="_nuclei.txt")
    os.close(fd)

    command = ["nuclei", "-target", target, "-output", temp_output_path]
    if options:
        command.extend(shlex.split(options))

    try:
        subprocess.run(command, capture_output=True, text=True, errors="replace")
        scan_results = parse_nuclei(temp_output_path)

        # Sanitize hostname/URL for filesystem storage directory creation
        clean_hostname = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").split('/')[0])
        # Check for environment variable override for timestamp before creating new one. If environment exists, use it; otherwise, generate a new timestamp.
        timestamp = os.environ.get("SWISSKNIFE_SCAN_TIMESTAMP", datetime.now().strftime("%Y%m%d_%H%M%S"))
        
        # Compute persistent dynamic path format: results_hostname_timestamp/tool_outputs
        output_dir = os.path.join(f"results_{clean_hostname}_{timestamp}", "tool_outputs")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        persistent_output_path = os.path.join(output_dir, "nuclei.txt")

        if scan_results["raw_output"]:
            with open(persistent_output_path, "w", encoding="utf-8") as f:
                f.write(scan_results["raw_output"])
        else:
            # Fallback placeholder write execution
            with open(persistent_output_path, "w", encoding="utf-8") as f:
                f.write("Nuclei execution completed. No findings captured.")

        return scan_results

    finally:
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
    print(f"\n▶ Starting Nuclei context-driven vulnerability component scan on {target}...")
    return run_nuclei(target, options)