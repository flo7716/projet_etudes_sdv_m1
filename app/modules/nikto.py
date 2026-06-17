import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text

def parse_nikto(output):
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

def run_nikto(target, options=""):

    command = [
        "nikto",
        "-h", target,
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    output = "\n".join(filter(None, [result.stdout, result.stderr]))
    return parse_nikto(output)


def run_nikto_interactive():
    target = prompt_text(
        "Enter target host/URL:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional nikto options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning nikto on {target}...")
    return run_nikto(target, options)