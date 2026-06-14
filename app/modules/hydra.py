import re
import shlex
import subprocess

from app.modules.interactive import prompt_text


def parse_hydra(output: str):
    findings = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Hydra valid credential lines look like:
        # [22][ssh] host: 192.168.1.1   login: root   password: toor
        m = re.match(
            r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+host:\s*(?P<host>\S+)"
            r"\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>\S+)",
            line,
        )
        if m:
            findings.append(
                f"Valid credential found — host: {m.group('host')}, "
                f"service: {m.group('service')} (port {m.group('port')}), "
                f"login: {m.group('login')}, password: {m.group('password')}"
            )
            continue

        # fallback: lines containing both login and password keywords
        lowered = line.lower()
        if "login" in lowered and ("pass" in lowered or "password" in lowered):
            # skip noise lines
            if not any(skip in lowered for skip in ["[data]", "[attempt]", "[warning]", "[error]", "0 of ", "1 of "]):
                findings.append(line)

    return {
        "cracked_passwords_count": len(findings),
        "findings": findings,
    }


def run_hydra(target, user="root", passlist="/usr/share/wordlists/rockyou.txt", options=""):
    command = [
        "hydra",
        "-l", user,
        "-P", passlist,
        target,
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