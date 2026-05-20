import subprocess
import xml.etree.ElementTree as ET


def parse_searchsploit(output):

    results = []

    for line in output.splitlines():

        if line.startswith("No exploits found"):
            continue

        if line.strip() == "":
            continue

        results.append(line.strip())

    return {
        "exploits_count": len(results),
        "exploits": results
    }

def run_searchsploit(options=""):

    command = [
        "searchsploit"
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_searchsploit(result.stdout)
