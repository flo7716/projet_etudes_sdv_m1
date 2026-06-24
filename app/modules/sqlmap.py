# app/modules/sqlmap.py
import os
import re
import shlex
import subprocess
import sys

from app.modules.interactive import prompt_text


def parse_sqlmap(output):
    """Parse l'output brut de la console sqlmap."""
    findings = []
    severity = "low"
    
    # 1. Détection de base de la vulnérabilité
    if "is vulnerable" in output or "confirming SQL injection" in output or "sqlmap identified the following injection point(s)" in output:
        findings.append("SQL Injection vulnerability detected and confirmed.")
        severity = "critical"
    
    # 2. Extraction des bases de données trouvées dans la console
    db_matches = re.findall(r"Database:\s+([^\s]+)", output)
    if db_matches:
        for db in set(db_matches):
            findings.append(f"Exposed Database: {db}")
        severity = "critical"
        
    return {
        "output": output,
        "raw_output": output,  # AJOUT CRUCIAL POUR L'ORCHESTRATEUR DE RAPPORT (report.py)
        "findings": findings,
        "severity": severity,
        "summary": "SQLmap injection testing completed." if not findings else "SQLmap confirmed critical SQL Injection."
    }


def _extract_sqlmap_log_dir(output: str):
    match = re.search(r"logged to text files under ['\"]([^'\"]+)['\"]", output, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _read_sqlmap_log_files(log_dir: str):
    if not log_dir or not os.path.isdir(log_dir):
        return []

    TEXT_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".xml", ".html"}
    log_files = []
    for root, _, files in os.walk(log_dir):
        for name in sorted(files):
            file_path = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue
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


def _attach_log_files(result: dict) -> dict:
    """
    Analyse les logs de dump (CSV/TXT) générés par SQLmap sur le disque
    et enrichit dynamiquement la section 'findings' pour le rapport PDF.
    """
    log_dir = _extract_sqlmap_log_dir(result.get("output", ""))
    if log_dir:
        result["log_dir"] = log_dir
        result["log_files"] = _read_sqlmap_log_files(log_dir)
        
        log_text = []
        for entry in result["log_files"]:
            log_text.append(f"=== {entry['name']} ===\n{entry['content']}\n")
            
            # --- ANALYSE DES FICHIERS DE LOG ET DES DUMPS ---
            if "dump" in entry["name"].lower() or entry["name"].endswith(".csv"):
                lines = [l for l in entry["content"].splitlines() if l.strip()]
                record_count = max(0, len(lines) - 1)
                
                result["findings"].append(
                    f"Data Exfiltration: Extracted table data '{entry['name']}' containing {record_count} records."
                )
                if "password" in entry["content"].lower() or "passwd" in entry["content"].lower():
                    result["findings"].append(
                        f"Critical Discovery: Plaintext or hashed credentials found inside extracted target logs."
                    )
            
            elif "table" in entry["name"].lower():
                result["findings"].append(f"Database Structure Harvested: See log file '{entry['name']}'.")

        result["log_summary"] = "\n".join(log_text).strip()
        
        # S'assurer que le raw_output exporté contient AUSSI le contenu textuel des tables exfiltrées
        if result["log_summary"]:
            result["raw_output"] = f"{result['output']}\n\n=== EXFILTRATED DATA LOGS ===\n{result['log_summary']}"
        
        # S'assurer que la sévérité passe au maximum si des données de tables ont été exfiltrées
        if any("Data Exfiltration" in f for f in result["findings"]):
            result["severity"] = "critical"
            
    return result


def run_sqlmap(target, options="", interactive=False):
    has_explicit_url = "-u " in options or "--url" in options
    
    if has_explicit_url:
        command = ["sqlmap"]
    else:
        command = ["sqlmap", "-u", target]

    if options:
        try:
            command.extend(shlex.split(options))
        except ValueError:
            command.extend(options.split())

    if interactive:
        if "--batch" in command:
            command.remove("--batch")
            
        output_chunks = []
        try:
            proc = subprocess.Popen(
                command,
                stdin=sys.stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=0,
            )

            if proc.stdout is None:
                raise RuntimeError("Failed to capture sqlmap process stdout")

            while True:
                char = proc.stdout.read(1)
                if not char:
                    break
                sys.stdout.write(char)
                sys.stdout.flush()
                output_chunks.append(char)

            proc.wait()
        except KeyboardInterrupt:
            output_chunks.append("\n[INFO] sqlmap session interrupted by the user.\n")

        parsed = parse_sqlmap("".join(output_chunks))
        return _attach_log_files(parsed)

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

    parsed = parse_sqlmap(output)
    return _attach_log_files(parsed)


def run_sqlmap_interactive():
    target = prompt_text(
        "Enter target URL (e.g. http://10.130.141.110/vuln.php?id=1):",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional sqlmap options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning interactive sqlmap on {target}...")
    return run_sqlmap(target, options, interactive=True)