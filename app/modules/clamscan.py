import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text

def parse_clamscan(output):
    lines = output.splitlines()

    results = []

    for line in lines:
        if "FOUND" in line or "ERROR" in line:
            results.append(line)

    return {
        "scan_issues_count": len(results),
        "scan_issues": results
    }

def run_clamscan(target, options=""):

    command = [
        "clamscan",
        target
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_clamscan(result.stdout)

def run_clamscan_interactive():
    target = prompt_text(
        "Enter target file or directory:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional clamscan options (leave empty for defaults):",
    )

    return run_clamscan(target, options)