import subprocess


def run_nmap(target):

    command = [
        "nmap",
        "-sV",
        "-sC",
        "-O",
        "-oX", "-",   # sortie XML
        target
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.stdout