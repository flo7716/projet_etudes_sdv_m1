import subprocess
import xml.etree.ElementTree as ET

def parse_gobuster(output):
    lines = output.splitlines()

    results = []

    for line in lines:
        #catches for lines with 200, 301, 302, 403, 500 status codes
        if any(status in line for status in ["200", "301", "302", "403", "500"]):
            results.append(line)

    return {
        "found_paths_count": len(results),
        "found_paths": results
    }



def run_gobuster(target, wordlist="/usr/share/wordlists/dirbuster/directory-list-1.0.txt", options=""):

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
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_gobuster(result.stdout)