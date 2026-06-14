import re
import subprocess

from app.modules.interactive import prompt_text


def parse_ffuf(output: str):
    findings = []

    # ffuf output line example (non-JSON mode):
    # /admin                  [Status: 200, Size: 4321, Words: 120, Lines: 89, Duration: 45ms]
    pattern = re.compile(
        r"^(?P<word>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+),"
        r"\s*Words:\s*(?P<words>\d+),\s*Lines:\s*(?P<lines>\d+)"
        r"(?:,\s*Duration:\s*(?P<duration>[\d]+ms))?\]",
        re.MULTILINE,
    )

    for m in pattern.finditer(output):
        word = m.group("word")
        status = m.group("status")
        size = m.group("size")
        duration = m.group("duration") or ""
        entry = f"{word} - HTTP {status} ({size} bytes" + (f", {duration}" if duration else "") + ")"
        findings.append(entry)

    # fallback: keep lines that look like hits from older ffuf output format
    if not findings:
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # skip headers / noise
            if any(line.startswith(skip) for skip in [
                "ffuf", "Time", "Size", "Lines", "Words", "Status",
                "Content-Type", "Location", "::", "/"
            ]):
                continue
            if re.search(r"\b(200|204|301|302|307|401|403)\b", line):
                findings.append(line)

    return {
        "findings_count": len(findings),
        "findings": findings,
    }


def run_ffuf(target, wordlist, options=""):
    command = [
        "ffuf",
        "-u", target,
        "-w", wordlist,
        "-t", "50",
        "-mc", "200,204,301,302,307,401,403",
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(command, capture_output=True, text=True)
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