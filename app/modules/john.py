import subprocess


def run_john(hash_file):

    command = [
        "john",
        hash_file
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return {
        "output": result.stdout
    }