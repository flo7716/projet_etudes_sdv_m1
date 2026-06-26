# app/modules/john.py
import os
import re
import subprocess
from datetime import datetime
import questionary
from app.modules.interactive import prompt_text

def parse_john(output: str):
    results = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(skip) for skip in ["Loaded", "No password hashes", "guesses", "0g ", "Warning:", "Press '", "Use the", "Session completed"]):
            continue
        results.append(stripped)

    severity = "critical" if len(results) > 0 else "low"

    return {
        "tool": "john",
        "findings": results,
        "severity": severity,
        "summary": f"Offline password cracking finished. Cracked {len(results)} crypt hashes successfully.",
        "raw_output": output
    }

def run_john(hash_file, wordlist="/usr/share/john/password.lst", options="", target_type="Basic hash", archive_type=None):
    command = ["john", f"--wordlist={wordlist}"]
    
    if target_type == "Windows hash":
        command.append("--format=nt")
    elif target_type == "/etc/shadow hash":
        command.append("--format=crypt")
    elif target_type == "Password protected archive (zip, rar)":
        command.append(f"--format={ (archive_type or 'zip').lower() }")
    elif target_type == "SSH key":
        command.append("--format=ssh")
    elif target_type == "Single crack":
        command.append("--single")

    if options:
        command.extend(options.split())
        
    command.append(hash_file)

    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    output = "\n".join(filter(None, [result.stdout, result.stderr]))
    
    # John alternative check logic: call --show to get cracked hashes
    show_cmd = ["john", "--show", hash_file]
    if "--format=" in " ".join(command):
        fmt = [opt for opt in command if opt.startswith("--format=")]
        show_cmd.append(fmt[0])
    
    show_res = subprocess.run(show_cmd, capture_output=True, text=True, errors="replace")
    combined_output = f"--- Runtime Exec Out ---\n{output}\n--- Show Cracked Hashes Out ---\n{show_res.stdout}"
    
    scan_results = parse_john(combined_output)

    # File pipeline confinement
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    persistent_path = os.path.join(output_dir, f"john_{timestamp}.txt")
    with open(persistent_path, "w", encoding="utf-8") as f:
        f.write(combined_output)

    return scan_results

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

    if target_type == "Password protected archive (zip, rar)":
        archive_type = questionary.select("Archive type:", choices=["zip", "rar"], default="zip").ask()
        if archive_type is None:
            raise KeyboardInterrupt("Input cancelled")

    wordlist = prompt_text("Wordlist path:", default="/usr/share/john/password.lst")
    options = prompt_text("Additional john options (leave empty for defaults):", default="")

    print(f"\n▶ Starting John the Ripper offline cryptographic cracking on {target_type}...")
    return run_john(hash_file, wordlist, options, target_type, archive_type)