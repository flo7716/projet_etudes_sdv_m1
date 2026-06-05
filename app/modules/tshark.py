import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text


def parse_tshark(output):
    lines = output.splitlines()

    results = []

    for line in lines:
        if "TCP" in line or "UDP" in line or "HTTP" in line:
            results.append(line)

    return {
        "packet_issues_count": len(results),
        "packet_issues": results
    }

def run_tshark(target, options=""):

    command = [
        "tshark",
        "-r",
        target
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_tshark(result.stdout)

def run_tshark_interactive():
    target = prompt_text(
        "Enter path to pcap file:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional tshark options (leave empty for defaults):",
    )

    return run_tshark(target, options)
