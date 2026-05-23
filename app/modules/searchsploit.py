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

def run_searchsploit(target, options=""):

    command = [
        "searchsploit",
        target
    ]
    if options:
        command.extend(options.split())

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )
    except FileNotFoundError as e:
        raise FileNotFoundError(
            "searchsploit is not installed or not available in PATH. "
            "Install SearchSploit / exploitdb and try again."
        ) from e

    if result.returncode != 0 and result.stderr:
        raise RuntimeError(f"searchsploit failed: {result.stderr.strip()}")

    return parse_searchsploit(result.stdout)
