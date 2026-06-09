import shlex
import subprocess

from app.modules.interactive import prompt_text


def parse_aircrack(output: str):
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return {
        "tool": "aircrack_ng",
        "lines_count": len(lines),
        "output": lines[-100:] if lines else [],
        "raw_output": output,
    }


def run_aircrack_ng(target: str, options: str = ""):
    command = ["aircrack-ng", target]

    if options:
        command.extend(shlex.split(options))

    result = subprocess.run(command, capture_output=True, text=True)
    output = "\n".join(filter(None, [result.stdout, result.stderr]))

    if result.returncode != 0:
        return {
            "tool": "aircrack_ng",
            "command": " ".join(command),
            "error": output or "aircrack-ng execution failed.",
        }

    return parse_aircrack(output)


def run_aircrack_ng_interactive():
    target = prompt_text(
        "Enter the capture file or handshake path:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional aircrack-ng options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning aircrack-ng on {target}...")
    return run_aircrack_ng(target, options)
