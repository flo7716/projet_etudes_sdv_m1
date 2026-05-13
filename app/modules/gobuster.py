import subprocess
import xml.etree.ElementTree as ET

def parse_gobuster(output):
    lines = output.splitlines()

    results = []

    for line in lines:
        if line.startswith("/"):
            results.append(line)

    return {
        "found_paths_count": len(results),
        "found_paths": results
    }



def run_gobuster(target, wordlist="/usr/share/wordlists/dirb/common.txt"):

    # ajoute http:// automatiquement
    if not target.startswith("http"):
        target = f"http://{target}"

    command = [
        "gobuster",
        "dir",
        "-u", target,
        "-w", wordlist,
        "-q"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_gobuster(result.stdout)