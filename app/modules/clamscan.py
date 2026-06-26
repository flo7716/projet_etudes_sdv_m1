# app/modules/clamscan.py
import os
import re
import subprocess
from datetime import datetime
from app.modules.interactive import prompt_text

def parse_clamscan(output: str):
    findings = []
    summary_data = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        if "FOUND" in line:
            m = re.match(r"^(.+):\\s+(.+)\\s+FOUND$", line)
            if m:
                findings.append(f"INFECTED: {m.group(1)} [{m.group(2)}]")
            else:
                findings.append(line)
            continue

        if "ERROR" in line:
            findings.append(f"ERROR: {line}")
            continue

        m = re.match(r"^(.+?):\\s+(\\d+)$", line)
        if m:
            summary_data[m.group(1).strip()] = int(m.group(2))

    infected_count = summary_data.get("Infected files", len([f for f in findings if "INFECTED" in f]))
    severity = "critical" if infected_count > 0 else "low"

    if not findings:
        findings.append(f"No threats detected. ({summary_data.get('Scanned files', 0)} files scanned)")

    return {
        "tool": "clamscan",
        "findings": findings,
        "severity": severity,
        "summary": f"Antivirus file compliance check completed. Identified {infected_count} active malware threat(s).",
        "raw_output": output,
    }

def run_clamscan(target, options=""):
    command = ["clamscan", target]
    if options:
        command.extend(options.split())

    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    output = "\n".join(filter(None, [result.stdout, result.stderr]))
    scan_results = parse_clamscan(output)

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
        
    persistent_path = os.path.join(output_dir, "clamscan_standalone_raw_output.txt")
    with open(persistent_path, "w", encoding="utf-8") as f:
        f.write(output)

    return scan_results

def run_clamscan_interactive():
    target = prompt_text(
        "Enter target file or directory:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional clamscan options (leave empty for defaults):",
        default="",
    )
    print(f"\n▶ Starting ClamAV compliance scan on {target}...")
    return run_clamscan(target, options)