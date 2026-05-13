import subprocess
import xml.etree.ElementTree as ET

def parse_john(output):

    results = []

    for line in output.splitlines():

        if line.startswith("Loaded") or line.startswith("No password hashes") or line.startswith("guesses") or line.startswith("0g 0p") or line.startswith("0g 0p") or line.startswith("0g 0t") or line.startswith("0g 0c"):
            continue

        if line.strip() == "":
            continue

        results.append(line.strip())

    return {
        "cracked_passwords_count": len(results),
        "cracked_passwords": results
    }


def run_john(hash_file, wordlist):

    command = [
        "john",
        "--wordlist=" + wordlist,
        hash_file
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_john(result.stdout)