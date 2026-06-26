# app/modules/nikto.py
import os
import re
import subprocess
from datetime import datetime
from app.modules.interactive import prompt_text

def parse_nikto(output: str):
    results = []
    severity = "low"

    for line in output.splitlines():
        line = line.strip()
        if line == "" or line.startswith("-") or line.startswith("|"):
            continue

        if line.startswith("+"):
            if any(skip in line for skip in ["Target IP:", "Target Hostname:", "Target Port:", "Platform:", "Start Time:", "Server:", "Failed to check for updates"]):
                continue
            item = line[1:].strip()
            results.append(item)
            
            item_lower = item.lower()
            if any(x in item_lower for x in ["rce", "exec", "vulnerable", "overflow", "cve-"]):
                severity = "critical"
            elif "injection" in item_lower or "unauthenticated" in item_lower:
                if severity != "critical": severity = "high"
            elif "finding" in item_lower or "leak" in item_lower:
                if severity not in ["critical", "high"]: severity = "medium"

    if severity == "low" and len(results) > 3:
        severity = "medium"

    return {
        "vulnerabilities_count": len(results),
        "vulnerabilities": results,
        "findings": results[:25],
        "severity": severity,
        "raw_output": output
    }

def run_nikto(target: str, options: str = ""):
    command = ["nikto", "-h", target]
    if options:
        command.extend(options.split())

    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    output = "\n".join(filter(None, [result.stdout, result.stderr]))
    scan_results = parse_nikto(output)

    # Sanitize hostname/URL for filesystem storage directory creation
    clean_hostname = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").split('/')[0])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Compute persistent dynamic path format: results_hostname_timestamp/tool_output
    output_dir = os.path.join(f"results_{clean_hostname}_{timestamp}", "tool_outputs")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    persistent_path = os.path.join(output_dir, "nikto_raw_output.txt")
    with open(persistent_path, "w", encoding="utf-8") as f:
        f.write(output)

    return scan_results

def run_nikto_interactive():
    target = prompt_text(
        "Enter target host/URL:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional nikto options (leave empty for defaults):",
        default="",
    )
    print(f"\n▶ Starting Nikto web security configuration scanner on {target}...")
    return run_nikto(target, options)