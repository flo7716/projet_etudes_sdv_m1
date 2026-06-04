import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text

def parse_sslyze(output):
    lines = output.splitlines()

    results = []

    for line in lines:
        if "Certificate" in line or "Cipher" in line or "Protocol" in line:
            results.append(line)

    return {
        "ssl_issues_count": len(results),
        "ssl_issues": results
    }

def run_sslyze(target, options=""):

    command = [
        "sslyze",
        target
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_sslyze(result.stdout)

def run_sslyze_interactive():
    target = prompt_text(
        "Enter target host:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional sslyze options (leave empty for defaults):",
    )

    return run_sslyze(target, options)

