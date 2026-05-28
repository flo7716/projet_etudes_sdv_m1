import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text


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


def run_hydra_interactive():
    target = prompt_text(
        "Enter target host:",
        validate=lambda x: len(x) > 0,
    )
    user = prompt_text(
        "Username to brute force:",
        default="root",
    )
    passlist = prompt_text(
        "Password list path:",
        default="/usr/share/wordlists/rockyou.txt",
    )
    options = prompt_text(
        "Additional hydra options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning hydra on {target}...")
    return run_hydra(target, user, passlist, options)

