import re
import select
import shlex
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
        try:
            command.extend(shlex.split(options))
        except ValueError:
            command.extend(options.split())

    prompt_patterns = [
        (
            re.compile(r"Do you want to skip test payloads specific for other DBMSes\? \[Y/n\]", re.IGNORECASE),
            "y"
        ),
        (
            re.compile(r"For the remaining tests, do you want to include all tests for 'MySQL' extending provided risk \(1\) value\? \[Y/n\]", re.IGNORECASE),
            "y"
        ),
        (
            re.compile(r"Injection not exploitable with NULL values\. Do you want to try with a random integer value for option '--union-char'\? \[Y/n\]", re.IGNORECASE),
            "y"
        ),
        (
            re.compile(r"GET parameter '.*' is vulnerable\. Do you want to keep testing the others \(if any\)\? \[y/N\]", re.IGNORECASE),
            "n"
        ),
    ]

    output_lines = []
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        if proc.stdout is None or proc.stdin is None:
            raise RuntimeError("Failed to capture sqlmap process streams")

        buffer = ""
        while proc.poll() is None:
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
            if proc.stdout in ready:
                chunk = proc.stdout.read(1024)
                if not chunk:
                    break
                output_lines.append(chunk)
                buffer += chunk
                for pattern, answer in prompt_patterns:
                    if pattern.search(buffer):
                        proc.stdin.write(answer + "\n")
                        proc.stdin.flush()
                        output_lines.append(f"[AUTO-ANSWER] {answer}\n")
                        buffer = ""
                        break

        # Read any remaining output after the process exits
        remaining = proc.stdout.read()
        if remaining:
            output_lines.append(remaining)
    except Exception as exc:
        output_lines.append(f"[ERROR] {exc}\n")

    return parse_sqlmap("".join(output_lines))