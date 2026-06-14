import re
import subprocess

from app.modules.interactive import prompt_text


def parse_clamscan(output: str):
    findings = []
    summary = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Infected file lines: "path/to/file: Eicar-Test-Signature FOUND"
        if "FOUND" in line:
            m = re.match(r"^(.+):\s+(.+)\s+FOUND$", line)
            if m:
                findings.append(f"INFECTED: {m.group(1)} [{m.group(2)}]")
            else:
                findings.append(line)
            continue

        if "ERROR" in line:
            findings.append(f"ERROR: {line}")
            continue

        # Summary section lines e.g. "Infected files: 0"
        m = re.match(r"^(.+?):\s+(\d+)$", line)
        if m:
            summary[m.group(1).strip()] = int(m.group(2))

    infected_count = summary.get("Infected files", len(findings))
    scanned_count = summary.get("Scanned files", None)

    if not findings:
        findings.append(
            f"No threats detected."
            + (f" ({scanned_count} file(s) scanned)" if scanned_count is not None else "")
        )

    return {
        "infected_count": infected_count,
        "scanned_count": scanned_count,
        "findings": findings,
        "summary": summary,
    }


def run_clamscan(target, options=""):
    command = ["clamscan", target]
    if options:
        command.extend(options.split())

    result = subprocess.run(command, capture_output=True, text=True)
    return parse_clamscan(result.stdout)


def run_clamscan_interactive():
    target = prompt_text(
        "Enter target file or directory:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional clamscan options (leave empty for defaults):",
        default="",
    )
    return run_clamscan(target, options)