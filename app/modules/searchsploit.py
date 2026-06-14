import re
import subprocess

from app.modules.interactive import prompt_text


def parse_searchsploit(output: str):
    findings = []
    in_table = False

    for line in output.splitlines():
        line_stripped = line.strip()

        if not line_stripped:
            continue

        # Skip header/separator lines
        if re.match(r"^[-=|]+$", line_stripped):
            in_table = True
            continue
        if line_stripped.lower().startswith("exploit title"):
            in_table = True
            continue
        if line_stripped.startswith("No exploits found"):
            continue
        if line_stripped.startswith("Shellcodes:"):
            break  # stop after exploits section

        # Parse table rows: "Title  |  Path"
        if in_table and "|" in line:
            parts = [p.strip() for p in line_stripped.split("|", 1)]
            if len(parts) == 2 and parts[0] and parts[1]:
                title, path = parts
                findings.append(f"{title} — {path}")
            continue

        # Fallback: non-table output lines
        if line_stripped and not line_stripped.startswith("-"):
            findings.append(line_stripped)

    return {
        "exploits_count": len(findings),
        "findings": findings,
    }


def run_searchsploit(target, options=""):
    command = ["searchsploit", target]
    if options:
        command.extend(options.split())

    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise FileNotFoundError(
            "searchsploit is not installed or not available in PATH. "
            "Install SearchSploit / exploitdb and try again."
        ) from e

    if result.returncode != 0 and result.stderr:
        raise RuntimeError(f"searchsploit failed: {result.stderr.strip()}")

    return parse_searchsploit(result.stdout)


def run_searchsploit_interactive():
    target = prompt_text(
        "Enter search term for searchsploit:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional searchsploit options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning searchsploit for {target}...")
    return run_searchsploit(target, options)