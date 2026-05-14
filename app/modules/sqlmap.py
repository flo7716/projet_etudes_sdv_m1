import subprocess
import json

def parse_sqlmap(output):
    # SQLmap output is complex, for simplicity, return raw output
    # In a real implementation, parse JSON if available
    return {
        "output": output
    }

def run_sqlmap(target, options=""):
    command = [
        "sqlmap",
        "-u", target,
        "--batch"
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_sqlmap(result.stdout)