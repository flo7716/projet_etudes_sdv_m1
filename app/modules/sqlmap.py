import os
import re
import shlex
import subprocess
import sys

from app.modules.interactive import prompt_text


def parse_sqlmap(output):
    # SQLmap output is complex, for simplicity, return raw output
    # In a real implementation, parse JSON if available
    return {
        "output": output
    }


def _should_prompt_for_sqlmap_output(line):
    return bool(
        "[Y/n]" in line
        or "[y/N]" in line
        or re.search(r"\b(do you want|do you want to|continue|choose|enter|try with|use the)\b", line, re.IGNORECASE)
    )


def _extract_sqlmap_log_dir(output: str):
    match = re.search(r"logged to text files under ['\"]([^'\"]+)['\"]", output, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _read_sqlmap_log_files(log_dir: str):
    if not log_dir or not os.path.isdir(log_dir):
        return []

    # Only include known text file extensions, skip binary files like session.sqlite
    TEXT_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".xml", ".html"}

    log_files = []
    for root, _, files in os.walk(log_dir):
        for name in sorted(files):
            file_path = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue  # ← skip session.sqlite and other binary files
            if os.path.isfile(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                        log_files.append({
                            "path": file_path,
                            "name": os.path.relpath(file_path, log_dir),
                            "content": handle.read(),
                        })
                except OSError:
                    continue
    return log_files


def _prompt_for_sqlmap_answer(prompt_text_line):
    default = ""
    if "[Y/n]" in prompt_text_line:
        default = "y"
    elif "[y/N]" in prompt_text_line:
        default = "n"

    answer = prompt_text(
        f"sqlmap prompt:\n{prompt_text_line.strip()}\nAnswer:",
        default=default,
    )
    return answer.strip() or default


def _attach_log_files(result: dict) -> dict:
    """Read sqlmap log files from disk and attach them to the result dict."""
    log_dir = _extract_sqlmap_log_dir(result.get("output", ""))
    if log_dir:
        result["log_dir"] = log_dir
        result["log_files"] = _read_sqlmap_log_files(log_dir)
        log_text = []
        for entry in result["log_files"]:
            log_text.append(f"=== {entry['name']} ===\n{entry['content']}\n")
        result["log_summary"] = "\n".join(log_text).strip()
    return result


def run_sqlmap(target, options="", interactive=False):
    command = ["sqlmap", "-u", target]
    if options:
        try:
            command.extend(shlex.split(options))
        except ValueError:
            command.extend(options.split())

    command.append("--batch")

    if interactive:
        output_lines = []
        try:
            proc = subprocess.Popen(
                command,
                stdin=sys.stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            if proc.stdout is None:
                raise RuntimeError("Failed to capture sqlmap process stdout")

            for line in proc.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                output_lines.append(line)

            proc.wait()
        except KeyboardInterrupt:
            output_lines.append("\n[INFO] sqlmap session interrupted by the user.\n")

        result = parse_sqlmap("".join(output_lines))
        return _attach_log_files(result)

    # Non-interactive: run with --batch and capture everything silently
    command.append("--batch")

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

        while True:
            line = proc.stdout.readline()
            if not line:
                break
            output_lines.append(line)

        remaining = proc.stdout.read()
        if remaining:
            output_lines.append(remaining)

        proc.wait()
    except KeyboardInterrupt:
        output_lines.append("\n[INFO] sqlmap session interrupted by the user.\n")
    except Exception as exc:
        output_lines.append(f"[ERROR] {exc}\n")

    result = parse_sqlmap("".join(output_lines))
    return _attach_log_files(result)


def run_sqlmap_interactive():
    target = prompt_text(
        "Enter target URL:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional sqlmap options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning sqlmap on {target}...")
    return run_sqlmap(target, options, interactive=True)