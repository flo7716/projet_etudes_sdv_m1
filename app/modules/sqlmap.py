# app/modules/sqlmap.py
import os
import re
import shlex
import subprocess
from datetime import datetime
from app.modules.interactive import prompt_text

def parse_sqlmap(output: str):
    findings = []
    severity = "low"
    
    if "is vulnerable" in output or "confirming SQL injection" in output or "sqlmap identified the following injection point(s)" in output:
        findings.append("SQL Injection vulnerability detected and confirmed.")
        severity = "critical"
    
    db_matches = re.findall(r"Database:\s+([^\s]+)", output)
    if db_matches:
        for db in set(db_matches):
            findings.append(f"Exposed Database Schema Target: {db}")
        severity = "critical"
        
    return {
        "output": output,
        "raw_output": output,
        "findings": findings,
        "severity": severity,
        "summary": "SQLmap injection testing completed." if not findings else "SQLmap confirmed critical SQL Injection."
    }

def run_sqlmap(target: str, options: str = ""):
    command = ["sqlmap", "-u", target]
    if options:
        command.extend(shlex.split(options))

    if "--batch" not in command:
        command.append("--batch")
        
    answers_hook = "skip specific=Y,include all=Y,random integer=Y,keep testing=N"
    if "--answers" not in command:
        command.extend(["--answers", answers_hook])

    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=300
        )
        output = proc.stdout
    except subprocess.TimeoutExpired as te:
        output = str(te.stdout if te.stdout else "") + "\n[ERROR] SQLmap exceeded maximum pipeline execution timeout.\n"
    except KeyboardInterrupt:
        output = "\n[INFO] sqlmap session interrupted by the user.\n"
    except Exception as exc:
        output = f"[ERROR] Execution failed: {exc}\n"

    scan_results = parse_sqlmap(output)

    # Sanitize target URL for filesystem storage directory creation
    clean_hostname = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").split('/')[0])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Compute persistent dynamic path format: results_hostname_timestamp/tool_output
    output_dir = os.path.join(f"results_{clean_hostname}_{timestamp}", "tool_output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    persistent_path = os.path.join(output_dir, "sqlmap.txt")
    with open(persistent_path, "w", encoding="utf-8") as f:
        f.write(scan_results["raw_output"])

    return scan_results

def run_sqlmap_interactive():
    target = prompt_text(
        "Enter target URL (e.g. http://10.130.141.110/vuln.php?id=1):",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional sqlmap options (leave empty for defaults):",
        default="",
    )
    print(f"\n▶ Starting SQLmap database parameter automated assessment on {target}...")
    return run_sqlmap(target, options)