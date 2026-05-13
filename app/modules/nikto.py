import subprocess
import xml.etree.ElementTree as ET

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
        "-h",
        target
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_nikto(result.stdout)