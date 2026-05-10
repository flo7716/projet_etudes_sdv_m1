import subprocess


def run_nikto(target):

    command = [
        "nikto",
        "-h",
        target
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return {
        "output": result.stdout
    }