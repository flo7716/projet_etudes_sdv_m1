import json
import os
import re
import subprocess
import tempfile

from app.modules.interactive import prompt_text


def parse_ffuf(json_path: str):
    """
    Parse le fichier de sortie JSON natif de FFUF.
    Garantit l'absence totale d'erreurs d'expressions régulières ou de pollution textuelle.
    """
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
            
            # explicit filtering of noise or empty entries
            if input_word.startswith("#") or not input_word:
                continue
                
            status = res.get("status", 0)
            size = res.get("length", 0) or res.get("size", 0)
            
            # properly format the findings entry with HTTP status and size
            entry = f"/{input_word} - HTTP {status} ({size} bytes)"
            findings.append(entry)
            
        raw_content = json.dumps(data, indent=2)
        
    except Exception as e:
        raw_content = f"Error parsing JSON file: {str(e)}"
        
    return findings, raw_content


def run_ffuf(target, wordlist, options=""):
    # 1. Clean and normalize the target URL for FFUF
    target = target.strip("'\"")
    if "FUZZ" not in target:
        if not target.startswith(("http://", "https://")):
            target = f"http://{target.rstrip('/')}/FUZZ"
        else:
            target = f"{target.rstrip('/')}/FUZZ"

    # 2. Creation of a temporary file for FFUF JSON output
    fd, temp_json_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    # 2. Smart and secure construction of arguments
    # We isolate the additional options provided by the user
    user_opts = []
    if options:
        # We cut the options string into a list, stripping quotes to avoid shell injection issues
        user_opts = [opt.strip("'\"") for opt in options.split() if opt.strip()]

    # If the user has specified a target URL with -u, we extract it to override the default target and remove the duplicate.
    if "-u" in user_opts:
        try:
            idx = user_opts.index("-u")
            if idx + 1 < len(user_opts):
                target = user_opts[idx + 1]
                # We remove the -u and its argument from the user options to avoid duplication
                del user_opts[idx:idx + 2]
        except Exception:
            pass

    # Execution of the FFUF command with the constructed arguments
    command = [
        "ffuf",
        "-u", target,
        "-w", wordlist,
        "-t", "50",
        "-mc", "200,204,301,302,307,401,403",
        "-o", temp_json_path,
        "-of", "json"
    ]
    
    # We append the user-provided options to the command, ensuring they are properly sanitized and do not introduce shell injection vulnerabilities
    command.extend(user_opts)

    try:
        # Ffuf is executed in a subprocess, capturing both stdout and stderr for comprehensive reporting
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        
        # Extraction of structured findings and raw output from the FFUF JSON file
        findings, parsed_raw = parse_ffuf(temp_json_path)
        
        # If the JSON parsing fails or yields no findings, we fall back to using the actual stdout/stderr for error reporting
        # This ensures that even if FFUF fails to produce a valid JSON output, we still capture the relevant information for debugging and reporting purposes
        # We use the actual stdout/stderr for error reporting if the JSON parsing fails or yields no findings
        if not findings and (not parsed_raw or "No JSON output file found" in parsed_raw):
            raw_output = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        else:
            raw_output = parsed_raw
            
    finally:
        # Systematic cleanup of the temporary JSON file to prevent clutter and potential data leaks
        if os.path.exists(temp_json_path):
            os.remove(temp_json_path)

    # 3. Severity assessment based on the findings, with a focus on sensitive files and administrative endpoints
    severity = "low"
    for item in findings:
        item_lower = item.lower()
        if any(keyword in item_lower for keyword in [".env", ".git", "config", "backup", "secret", "db.php"]):
            severity = "critical"
            break
        elif any(keyword in item_lower for keyword in ["admin", "login", "auth", "panel", "vulnerabilities"]):
            if severity != "critical":
                severity = "high"

    # Returning a structured report with all relevant information, including the findings, severity, and raw output for further analysis or reporting
    return {
        "tool": "ffuf",
        "target": target,
        "findings": findings,
        "severity": severity,
        "summary": f"Fuzzing completed. Found {len(findings)} accessible paths/endpoints.",
        "objective": "Enumerate web server directories, hidden resources, and sensitive path locations.",
        "recommendations": ["Harden directory permissions, implement access-control lists (ACLs) and restrict access to administrative interfaces."],
        "raw_output": raw_output
    }


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
    print(f"\nRunning ffuf on {target}...")
    return run_ffuf(target, wordlist, options)