import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text

def parse_nikto(output):

    results = []

    for line in output.splitlines():
        line = line.strip()
        if line == "":
            continue

        if line.startswith("-"):
            continue

        if line.startswith("+"):
            if any(skip in line for skip in [
                "Target IP:",
                "Target Hostname:",
                "Target Port:",
                "Platform:",
                "Start Time:",
                "Server:",
                "Failed to check for updates"
            ]):
                continue
            results.append(line[1:].strip())
            continue

        if line.startswith("|"):
            continue

        results.append(line)

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