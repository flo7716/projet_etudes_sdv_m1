# app/modules/hydra.py
import os
import re
import shlex
import subprocess
from datetime import datetime
from app.modules.interactive import prompt_text

def parse_hydra(output: str):
    findings = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        m = re.match(
            r"\[(?P<port>\d+)\]\[(?P<service>[^\\]]+)\]\s+host:\s*(?P<host>\S+)"
            r"\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)",
            line,
        )
        if m:
            findings.append(
                f"Valid credential found — host: {m.group('host')}, "
                f"service: {m.group('service')} (port {m.group('port')}), "
                f"login: {m.group('login')}, password: {m.group('password')}"
            )
            continue

        lowered = line.lower()
        if "login" in lowered and ("pass" in lowered or "password" in lowered):
            if not any(skip in lowered for skip in ["[data]", "[attempt]", "[warning]", "[error]", "0 of ", "1 of "]):
                findings.append(line)

    severity = "critical" if len(findings) > 0 else "low"

    return {
        "tool": "hydra",
        "findings": findings,
        "severity": severity,
        "summary": f"Network password brute-force completed. Extracted {len(findings)} valid credential pairs.",
        "raw_output": output,
    }

def run_hydra(target, user="root", passlist="/usr/share/wordlists/rockyou.txt", options=""):
    command = ["hydra", "-l", user, "-P", passlist, target]
    if options:
        command.extend(shlex.split(options))

    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    output = result.stdout or ""
    scan_results = parse_hydra(output)

    # Sanitize hostname/URL for filesystem storage directory creation
    clean_hostname = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").replace("ftp://", "").replace("ssh://", "").split('/')[0])
    # Check for environment variable override for timestamp before creating new one. If environment exists, use it; otherwise, generate a new timestamp and export it.
    timestamp = os.environ.get("SWISSKNIFE_SCAN_TIMESTAMP")
    if not timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.environ["SWISSKNIFE_SCAN_TIMESTAMP"] = timestamp
    
    # Compute persistent dynamic path format: results_hostname_timestamp/tool_output
    output_dir = os.path.join(f"results_{clean_hostname}_{timestamp}", "tool_outputs")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    persistent_path = os.path.join(output_dir, "hydra_standalone_raw_output.txt")
    with open(persistent_path, "w", encoding="utf-8") as f:
        f.write(output)

    return scan_results

def run_hydra_interactive():
    target = prompt_text(
        "Enter target host:",
        validate=lambda x: len(x) > 0,
    )
    user = prompt_text(
        "Username to brute force:",
        default="root",
    )
    passlist = prompt_text(
        "Password list path:",
        default="/usr/share/wordlists/rockyou.txt",
    )
    options = prompt_text(
        "Additional hydra options (leave empty for defaults):",
        default="",
    )
    print(f"\n▶ Starting Hydra parallel brute-force attack on {target}...")
    return run_hydra(target, user, passlist, options)