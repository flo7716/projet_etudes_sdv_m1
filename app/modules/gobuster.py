import subprocess


def run_gobuster(target):

    command = [
        "gobuster",
        "dir",
        "-u",
        target,
        "-w",
        "/usr/share/wordlists/dirb/common.txt"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return {
        "output": result.stdout
    }