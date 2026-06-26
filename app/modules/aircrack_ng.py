# app/modules/aircrack_ng.py
import os
import re
import shlex
import subprocess
from datetime import datetime
from app.modules.interactive import prompt_text

def parse_aircrack(output: str):
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    findings = []
    severity = "low"
    
    # Check for cracked keys or successful handshakes
    for line in lines:
        if "KEY FOUND!" in line or "Cracked successfully" in line:
            findings.append(line)
            severity = "critical"
            
    if not findings and lines:
        # Capture the last meaningful line as context
        findings.append(lines[-1])

    return {
        "tool": "aircrack_ng",
        "findings": findings,
        "severity": severity,
        "summary": f"Wireless audit completed. Found {len(findings)} key matching signatures.",
        "raw_output": output,
    }

def run_aircrack_ng(target: str, options: str = ""):
    command = ["aircrack-ng", target]
    if options:
        command.extend(shlex.split(options))

    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    output = "\n".join(filter(None, [result.stdout, result.stderr]))

    if result.returncode != 0 and not output:
        return {
            "tool": "aircrack_ng",
            "findings": [],
            "severity": "low",
            "summary": "Wireless auditing failed or execution returned an unexpected status code.",
            "raw_output": output or "aircrack-ng execution failed.",
        }

    scan_results = parse_aircrack(output)

    # Sanitize hostname/URL for filesystem storage directory creation
    clean_hostname = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").split('/')[0])
    # Check for environment variable override for timestamp before creating new one. If environment exists, use it; otherwise, generate a new timestamp and export it.
    timestamp = os.environ.get("SWISSKNIFE_SCAN_TIMESTAMP")
    if not timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.environ["SWISSKNIFE_SCAN_TIMESTAMP"] = timestamp
    
    # Compute persistent dynamic path format: results_hostname_timestamp/tool_output
    output_dir = os.path.join(f"results_{clean_hostname}_{timestamp}", "tool_outputs")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    persistent_path = os.path.join(output_dir, "aircrack_standalone_raw_output.txt")
    with open(persistent_path, "w", encoding="utf-8") as f:
        f.write(output)

    return scan_results

def run_aircrack_ng_interactive():
    target = prompt_text(
        "Enter the capture file or handshake path:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional aircrack-ng options (leave empty for defaults):",
        default="",
    )
    print(f"\n▶ Starting aircrack-ng scan on {target}...")
    return run_aircrack_ng(target, options)