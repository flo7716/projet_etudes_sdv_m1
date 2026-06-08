import os
import shutil
import subprocess
import tempfile

import questionary

from app.modules.interactive import prompt_text

def parse_john(output):

    results = []

    for line in output.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("Loaded") or stripped.startswith("No password hashes") or stripped.startswith("guesses") or stripped.startswith("0g ") or stripped.startswith("Warning:") or stripped.startswith("Press '") or stripped.startswith("Use the") or stripped.startswith("Session completed"):
            continue

        results.append(stripped)

    return {
        "cracked_passwords_count": len(results),
        "cracked_passwords": results
    }


def build_john_options(target_type, options="", archive_type=None):
    """Build John CLI options for the selected cracking scenario."""
    command_options = []

    if target_type == "Windows hash":
        command_options.append("--format=nt")
    elif target_type == "/etc/shadow hash":
        command_options.append("--format=crypt")
    elif target_type == "Password protected archive (zip, rar)":
        command_options.append("--format=" + (archive_type or "zip").lower())
    elif target_type == "SSH key":
        command_options.append("--format=ssh")
    elif target_type == "Single crack":
        command_options.append("--single")

    if options:
        command_options.extend(options.split())

    return command_options


def _tool_path(name):
    return shutil.which(name) or name


def _prepare_hash_file(target_type, hash_file, archive_type=None, extra_input=None):
    """Convert a target file into a John-compatible hash file when needed."""
    temp_file = None

    if target_type == "Password protected archive (zip, rar)":
        if archive_type == "rar":
            tool = _tool_path("rar2john")
        else:
            tool = _tool_path("zip2john")

        result = subprocess.run([tool, hash_file], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout or f"Failed to convert {archive_type} archive")

        temp_file = tempfile.NamedTemporaryFile("w", delete=False, prefix="john-", suffix=".txt")
        temp_file.write(result.stdout)
        temp_file.close()
        return temp_file.name

    if target_type == "SSH key":
        ssh_tool = _tool_path("ssh2john.py")
        if os.path.exists("/usr/share/john/ssh2john.py"):
            ssh_tool = "/usr/share/john/ssh2john.py"

        result = subprocess.run(["python3", ssh_tool, hash_file], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout or "Failed to convert SSH key")

        temp_file = tempfile.NamedTemporaryFile("w", delete=False, prefix="john-", suffix=".txt")
        temp_file.write(result.stdout)
        temp_file.close()
        return temp_file.name

    if target_type == "/etc/shadow hash":
        if not extra_input:
            raise RuntimeError("A /etc/passwd file is required for /etc/shadow cracking")

        result = subprocess.run([_tool_path("unshadow"), extra_input, hash_file], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout or "Failed to unshadow the password file")

        temp_file = tempfile.NamedTemporaryFile("w", delete=False, prefix="john-", suffix=".txt")
        temp_file.write(result.stdout)
        temp_file.close()
        return temp_file.name

    return hash_file


def run_john(hash_file, wordlist, options="", target_type="Basic hash", archive_type=None, extra_input=None):
    temp_hash_file = None

    try:
        temp_hash_file = _prepare_hash_file(target_type, hash_file, archive_type=archive_type, extra_input=extra_input)

        command = [
            _tool_path("john"),
            "--wordlist=" + wordlist,
            temp_hash_file,
            *build_john_options(target_type, options, archive_type=archive_type),
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        return parse_john(result.stdout + (result.stderr or ""))
    finally:
        if temp_hash_file and temp_hash_file != hash_file and os.path.exists(temp_hash_file):
            os.remove(temp_hash_file)


def run_john_interactive():
    target_type = questionary.select(
        "What do you want to crack?",
        choices=[
            "Basic hash",
            "Windows hash",
            "/etc/shadow hash",
            "Single crack",
            "Password protected archive (zip, rar)",
            "SSH key",
        ],
        default="Basic hash",
    ).ask()

    if target_type is None:
        raise KeyboardInterrupt("Input cancelled")

    hash_file = prompt_text("Enter hash file path or archive/key path:", validate=lambda x: len(x) > 0)

    archive_type = None
    extra_input = None

    if target_type == "Password protected archive (zip, rar)":
        archive_type = questionary.select(
            "Archive type:",
            choices=["zip", "rar"],
            default="zip",
        ).ask()
        if archive_type is None:
            raise KeyboardInterrupt("Input cancelled")

    if target_type == "/etc/shadow hash":
        extra_input = prompt_text("Path to /etc/passwd file:", validate=lambda x: len(x) > 0)

    if target_type == "SSH key":
        hash_file = prompt_text("Path to the private SSH key file:", validate=lambda x: len(x) > 0)

    wordlist = prompt_text("Wordlist path:", default="/usr/share/john/password.lst")
    options = prompt_text("Additional john options (leave empty for defaults):", default="")

    print(f"\nRunning john for {target_type} using {hash_file}...")
    return run_john(hash_file, wordlist, options, target_type=target_type, archive_type=archive_type, extra_input=extra_input)