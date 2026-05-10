import subprocess


def run_gobuster(target):

    # ajoute http:// automatiquement
    if not target.startswith("http"):
        target = f"http://{target}"

    command = [
        "gobuster",
        "dir",
        "-u", target,
        "-w", "/usr/share/wordlists/dirb/common.txt",
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