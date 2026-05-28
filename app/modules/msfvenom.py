import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text

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


def run_msfvenom_interactive():
    options = prompt_text(
        "Enter msfvenom options (e.g., -p windows/meterpreter/reverse_tcp LHOST=<IP>)",
        default="",
    )
    print(f"\nGenerating payload with msfvenom...")
    return run_msfvenom(options)
