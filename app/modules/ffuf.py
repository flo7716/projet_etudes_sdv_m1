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
            
            # Filtrage explicite des lignes de commentaires des dictionnaires de SecLists
            if input_word.startswith("#") or not input_word:
                continue
                
            status = res.get("status", 0)
            size = res.get("length", 0) or res.get("size", 0)
            
            # Formatage propre identique à Gobuster pour l'affichage final
            entry = f"/{input_word} - HTTP {status} ({size} bytes)"
            findings.append(entry)
            
        raw_content = json.dumps(data, indent=2)
        
    except Exception as e:
        raw_content = f"Error parsing JSON file: {str(e)}"
        
    return findings, raw_content


def run_ffuf(target, wordlist, options=""):
    # 1. Nettoyage et normalisation de la target par défaut
    target = target.strip("'\"")
    if "FUZZ" not in target:
        if not target.startswith(("http://", "https://")):
            target = f"http://{target.rstrip('/')}/FUZZ"
        else:
            target = f"{target.rstrip('/')}/FUZZ"

    # Création du fichier temporaire pour stocker le JSON de FFUF
    fd, temp_json_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    # 2. Construction intelligente et sécurisée des arguments
    # On isole les options supplémentaires de l'utilisateur
    user_opts = []
    if options:
        # On découpe en préservant les blocs mais en nettoyant les quotes malencontreuses
        user_opts = [opt.strip("'\"") for opt in options.split() if opt.strip()]

    # Si l'utilisateur a configuré son propre "-u <url>" dans les options additionnelles,
    # on extrait cette URL pour écraser la target par défaut et on retire le doublon.
    if "-u" in user_opts:
        try:
            idx = user_opts.index("-u")
            if idx + 1 < len(user_opts):
                target = user_opts[idx + 1]
                # On supprime le "-u" et sa valeur de la liste des options utilisateur
                del user_opts[idx:idx + 2]
        except Exception:
            pass

    # Base de la commande d'exécution
    command = [
        "ffuf",
        "-u", target,
        "-w", wordlist,
        "-t", "50",
        "-mc", "200,204,301,302,307,401,403",
        "-o", temp_json_path,
        "-of", "json"
    ]
    
    # On ajoute les options utilisateur nettoyées
    command.extend(user_opts)

    try:
        # Exécution du binaire ffuf sans lever d'exception bloquante
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        
        # Extraction des données structurées depuis le JSON temporaire
        findings, parsed_raw = parse_ffuf(temp_json_path)
        
        # Si le fichier JSON est inexistant ou vide (erreur de syntaxe globale de ffuf),
        # on utilise le stdout/stderr réel pour alimenter le rapport d'erreur technique
        if not findings and (not parsed_raw or "No JSON output file found" in parsed_raw):
            raw_output = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        else:
            raw_output = parsed_raw
            
    finally:
        # Nettoyage systématique du fichier d'échange éphémère
        if os.path.exists(temp_json_path):
            os.remove(temp_json_path)

    # 3. Calcul de la sévérité globale
    severity = "low"
    for item in findings:
        item_lower = item.lower()
        if any(keyword in item_lower for keyword in [".env", ".git", "config", "backup", "secret", "db.php"]):
            severity = "critical"
            break
        elif any(keyword in item_lower for keyword in ["admin", "login", "auth", "panel", "vulnerabilities"]):
            if severity != "critical":
                severity = "high"

    # Objet de retour normalisé (avec les clés attendues par tools_renderer.py)
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