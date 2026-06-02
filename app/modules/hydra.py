import shlex
import subprocess
from app.modules.interactive import prompt_text


def parse_hydra(output):
    results = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        lowered = line.lower()
        if lowered.startswith("hydra") or lowered.startswith("hydra("):
            continue
        if lowered.startswith("[data]") or lowered.startswith("[attempt]") or lowered.startswith("[warning]") or lowered.startswith("[error]"):
            continue
        if lowered.startswith("0 of ") or lowered.startswith("1 of ") or lowered.startswith("2 of ") or lowered.startswith("3 of ") or lowered.startswith("4 of ") or lowered.startswith("5 of ") or lowered.startswith("6 of ") or lowered.startswith("7 of ") or lowered.startswith("8 of ") or lowered.startswith("9 of "):
            continue
        if "login" in lowered and ("pass" in lowered or "password" in lowered):
            results.append(line)

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
        command.extend(shlex.split(options))

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    return parse_hydra(result.stdout or "")


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

