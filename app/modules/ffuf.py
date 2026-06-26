# app/modules/ffuf.py
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from app.modules.interactive import prompt_text

def parse_ffuf(json_path: str):
    findings = []
    raw_content = ""
    
    if not os.path.exists(json_path):
        return findings, "No JSON output file found."

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        results_list = data.get("results", [])
        for res in results_list:
            input_word = res.get("input", {}).get("FUZZ", "") or res.get("input", {}).get("value", "")
            if not input_word:
                continue
                
            input_word = str(input_word).strip()
            if input_word.startswith("#") or not input_word:
                continue
                
            status = res.get("status", 0)
            size = res.get("length", 0) or res.get("size", 0)
            
            entry = f"/{input_word} - HTTP {status} ({size} bytes)"
            findings.append(entry)
            
        raw_content = json.dumps(data, indent=2)
        
    except Exception as e:
        raw_content = f"Failed to parse internal FFUF payload definitions: {str(e)}"
        
    return findings, raw_content

def run_ffuf(target: str, wordlist: str, options: str = ""):
    # Use standard operating system unique temporal file token generators
    fd, temp_json_path = tempfile.mkstemp(suffix="_ffuf.json")
    os.close(fd)

    command = ["ffuf", "-u", target, "-w", wordlist, "-o", temp_json_path, "-of", "json"]
    if options:
        command.extend(options.split())

    try:
        subprocess.run(command, capture_output=True, text=True, errors="replace")
        findings, raw_output = parse_ffuf(temp_json_path)

        severity = "low"
        for item in findings:
            item_lower = item.lower()
            if any(keyword in item_lower for keyword in [".env", ".git", "config", "backup", "secret", "db.php"]):
                severity = "critical"
                break
            elif any(keyword in item_lower for keyword in ["admin", "login", "auth", "panel", "vulnerabilities"]):
                if severity != "critical":
                    severity = "high"

        scan_results = {
            "tool": "ffuf",
            "target": target,
            "findings": findings,
            "severity": severity,
            "summary": f"Fuzzing completed. Found {len(findings)} accessible paths/endpoints.",
            "raw_output": raw_output
        }

        # Sanitize hostname/URL for filesystem storage directory creation
        clean_hostname = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").split('/')[0])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Compute persistent dynamic path format: results_hostname_timestamp/tool_output
        output_dir = os.path.join(f"results_{clean_hostname}_{timestamp}", "tool_outputs")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        persistent_path = os.path.join(output_dir, "ffuf_raw_output.txt")
        with open(persistent_path, "w", encoding="utf-8") as f:
            f.write(scan_results["raw_output"])

        return scan_results

    finally:
        if os.path.exists(temp_json_path):
            os.remove(temp_json_path)

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
    print(f"\n▶ Running FFUF automated parameter and resource fuzzing on {target}...")
    return run_ffuf(target, wordlist, options)