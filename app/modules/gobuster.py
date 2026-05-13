import subprocess


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

    return {
        "target": target,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    }