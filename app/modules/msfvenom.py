import subprocess
import xml.etree.ElementTree as ET

def parse_msfvenom(output):

    results = []

    for line in output.splitlines():

        if line.startswith("No platform was selected") or line.startswith("No encoder or bad output format specified") or line.startswith("Use of this module requires Metasploit Pro"):
            continue

        if line.strip() == "":
            continue

        results.append(line.strip())

    return {
        "payloads_count": len(results),
        "payloads": results
    }

def run_msfvenom(options=""):

    command = [
        "msfvenom"
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_msfvenom(result.stdout)
