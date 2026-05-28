import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text

def parse_nikto(output):

    results = []

    for line in output.splitlines():

        if line.startswith("+") or line.startswith("-") or line.startswith("|"):
            continue

        if line.strip() == "":
            continue

        results.append(line.strip())

    return {
        "vulnerabilities_count": len(results),
        "vulnerabilities": results
    }


def run_nikto(target, options=""):

    command = [
        "nikto",
        "-h", target,
        "-maxtime", "2m",
        "-Tuning", "x"
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_nikto(result.stdout)


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