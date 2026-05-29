import subprocess
from app.modules.interactive import prompt_text
def parse_ffuf(output):

    results = []

    for line in output.splitlines():

        if line.startswith("ffuf") or line.startswith("Time") or line.startswith("Size") or line.startswith("Lines") or line.startswith("Words") or line.startswith("Status") or line.startswith("Content-Type") or line.startswith("Location"):
            continue

        if line.strip() == "":
            continue

        results.append(line.strip())

    return {
        "vulnerabilities_count": len(results),
        "vulnerabilities": results
    }

def run_ffuf(target, wordlist, options=""):

    command = [
        "ffuf",
        "-u", target,
        "-w", wordlist,
        "-t", "50",
        "-mc", "200,204,301,302,307,401,403"
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_ffuf(result.stdout)


def run_ffuf_interactive():
    target = prompt_text(
        "Enter target URL (use FUZZ where you want to fuzz):",
        validate=lambda x: "FUZZ" in x,
    )
    wordlist = prompt_text(
        "Wordlist path:",
        default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    )
    options = prompt_text(
        "Additional ffuf options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning ffuf on {target}...")
    return run_ffuf(target, wordlist, options)


