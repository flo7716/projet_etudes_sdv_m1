import re
import subprocess
from app.modules.interactive import prompt_text


def parse_gobuster(output):
    findings = []

    pattern = re.compile(
        r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s*\[Size:\s*(?P<size>\d+)\]"
        r"(?:\s*\[--> (?P<redirect>\S+)\])?"
    )

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        match = pattern.match(line)
        if match:
            path = match.group("path")
            status = match.group("status")
            size = match.group("size")
            redirect = match.group("redirect")

            entry = f"{path} - HTTP {status} ({size} bytes)"
            if redirect:
                entry += f", redirects to {redirect}"
            findings.append(entry)
            continue

        if any(status in line for status in ["200", "301", "302", "403", "500"]):
            findings.append(line)

    # --- SEVERITY CALCULATION ---
    severity = "low"
    for item in findings:
        item_lower = item.lower()
        # Sensitive files or directories -> Critical
        if any(keyword in item_lower for keyword in [".env", ".git", "config", "backup", "secret", "passwd", "shadow"]):
            severity = "critical"
            break  
        # Admin panels or login pages -> High
        elif any(keyword in item_lower for keyword in ["admin", "login", "wp-admin", "cpanel", "dashboard"]):
            if severity != "critical":
                severity = "high"

    return {
        "found_paths_count": len(findings),
        "findings": findings,
        "severity": severity,
        "raw_output": output
    }


def run_gobuster(target, wordlist="/usr/share/wordlists/dirbuster/directory-list-1.0.txt", options=""):

    if not wordlist:
        wordlist = "/usr/share/wordlists/dirbuster/directory-list-1.0.txt"

    # adds http:// automatically if not present, as gobuster requires a full URL
    if not target.startswith("http"):
        target = f"http://{target}"

    command = [
        "gobuster",
        "dir",
        "-u", target,
        "-w", wordlist,
        "-q"
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_gobuster(result.stdout)


def run_gobuster_interactive():
    target = prompt_text(
        "Enter target host/URL:",
        validate=lambda x: len(x) > 0,
    )
    wordlist = prompt_text(
        "Wordlist path:",
        default="/usr/share/wordlists/dirbuster/directory-list-1.0.txt",
    )
    options = prompt_text(
        "Additional gobuster options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning gobuster on {target}...")
    return run_gobuster(target, wordlist, options)