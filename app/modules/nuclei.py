import shlex
import subprocess

from app.modules.interactive import prompt_text


def parse_nuclei(output_file: str):

    with open(output_file, "r") as f:
        output = f.read()

    lines = [line.strip() for line in output.splitlines() if line.strip()]

    findings = []
    for line in lines:
        # nuclei -o output lines look like:
        # [template-id] [protocol] [severity] target [extra]
        findings.append(line)

    return {
        "tool": "nuclei",
        "lines_count": len(lines),
        "findings": findings[:25],
        "raw_output": output[:4000],
    }


def run_nuclei(target: str, options: str = ""):
    command = ["nuclei", "-target", target, "-o", "nuclei_$(date +%Y%m%d_%H%M%S).txt"]

    if options:
        command.extend(shlex.split(options))

    result = subprocess.run(command, capture_output=True, text=True)
    output = "\n".join(filter(None, [result.stdout, result.stderr]))

    if result.returncode != 0:
        return {
            "tool": "nuclei",
            "command": " ".join(command),
            "error": output or "nuclei scan failed.",
        }

    return parse_nuclei("nuclei_$(date +%Y%m%d_%H%M%S).txt")


def run_nuclei_interactive():
    target = prompt_text(
        "Enter target URL or host:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional nuclei options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning nuclei on {target}...")
    return run_nuclei(target, options)