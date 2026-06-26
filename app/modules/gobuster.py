# app/modules/gobuster.py
import os
import re
import subprocess
from datetime import datetime
from app.modules.interactive import prompt_text

def parse_gobuster(output: str):
    findings = []
    pattern = re.compile(
        r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s*\[Size:\s*(?P<size>\d+)\]"
        r"(?:\s*\[--> (?P<redirect>\S+)\])?"
    )

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        match = pattern.match(line)
        if match:
            path = match.group("path")
            status = match.group("status")
            size = match.group("size")
            redirect = match.group("redirect")

            entry = f"{path} - HTTP {status} ({size} bytes)"
            if redirect:
                entry += f", redirects to {redirect}"
            findings.append(entry)
            continue

        if any(status in line for status in ["200", "301", "302", "403", "500"]):
            findings.append(line)

    severity = "low"
    for item in findings:
        item_lower = item.lower()
        if any(keyword in item_lower for keyword in [".env", ".git", "config", "backup", "secret", "passwd", "shadow"]):
            severity = "critical"
            break  
        elif any(keyword in item_lower for keyword in ["admin", "login", "wp-admin", "cpanel", "dashboard"]):
            if severity != "critical":
                severity = "high"

    return {
        "found_paths_count": len(findings),
        "findings": findings,
        "severity": severity,
        "raw_output": output
    }

def run_gobuster(target: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-1.0.txt", options: str = ""):
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirbuster/directory-list-1.0.txt"

    if not target.startswith("http"):
        target = f"http://{target}"

    command = ["gobuster", "dir", "-u", target, "-w", wordlist, "-q"]
    if options:
        command.extend(options.split())

    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    output = "\n".join(filter(None, [result.stdout, result.stderr]))
    scan_results = parse_gobuster(output)

    # Sanitize hostname/URL for filesystem storage directory creation
    clean_hostname = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").split('/')[0])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Compute persistent dynamic path format: results_hostname_timestamp/tool_output
    output_dir = os.path.join(f"results_{clean_hostname}_{timestamp}", "tool_outputs")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    persistent_path = os.path.join(output_dir, "gobuster_raw_output.txt")
    with open(persistent_path, "w", encoding="utf-8") as f:
        f.write(output)

    return scan_results

def run_gobuster_interactive():
    target = prompt_text(
        "Enter target host/URL:",
        validate=lambda x: len(x) > 0,
    )
    wordlist = prompt_text(
        "Wordlist path:",
        default="/usr/share/wordlists/dirbuster/directory-list-1.0.txt",
    )
    options = prompt_text(
        "Additional gobuster options (leave empty for defaults):",
        default="",
    )
    print(f"\n▶ Starting Gobuster web directory discovery enumeration on {target}...")
    return run_gobuster(target, wordlist, options)