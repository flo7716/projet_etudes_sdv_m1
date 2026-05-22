import subprocess
import xml.etree.ElementTree as ET

def parse_hydra(output):

    results = []

    for line in output.splitlines():

        if line.startswith("Hydra") or line.startswith("0 of") or line.startswith("1 of") or line.startswith("2 of") or line.startswith("3 of") or line.startswith("4 of") or line.startswith("5 of") or line.startswith("6 of") or line.startswith("7 of") or line.startswith("8 of") or line.startswith("9 of"):
            continue

        if line.strip() == "":
            continue

        results.append(line.strip())

    return {
        "cracked_passwords_count": len(results),
        "cracked_passwords": results
    }

def run_hydra(target, user="root", passlist="/usr/share/wordlists/rockyou.txt", options=""):

    command = [
        "hydra",
        "-l", user,
        "-P", passlist,
        target
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_hydra(result.stdout)

