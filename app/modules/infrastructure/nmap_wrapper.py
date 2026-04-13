import nmap
import json
from datetime import datetime

class NmapModule:
    def __init__(self):
        # Initialise le scanner
        self.nm = nmap.PortScanner()
        
    def run_scan(self, target, scan_type="quick"):
        """
        Lance le scan et retourne un résultat structuré.
        scan_type: 'quick' (ping/top ports) ou 'full' (versions/OS)
        """
        print(f"[*] Démarrage du scan Nmap sur {target} ({scan_type})...")
        
        # Définition des arguments selon le besoin (Modularité)
        if scan_type == "quick":
            # Scan rapide: Ping + Top 100 ports
            args = "-sn -PE" # Ping sweep seulement pour commencer
        elif scan_type == "full":
            # Scan complet: Version detection (-sV), OS detection (-O), Script scan (-sC)
            # Attention: -O nécessite les droits root (sudo)
            args = "-sV -O -sC --top-ports 1000"
        else:
            args = "-sS"

        try:
            # Lancement du scan. 
            # arguments: options nmap
            # sudo=True peut être nécessaire si le docker user n'est pas root
            self.nm.scan(hosts=target, arguments=args)
            
            # On passe au parsing immédiatement
            return self._parse_results()

        except nmap.PortScannerError as e:
            return {"error": f"Erreur Nmap: {str(e)}"}
        except Exception as e:
            return {"error": f"Erreur inattendue: {str(e)}"}

    def _parse_results(self):
        """
        Nettoie les données brutes de Nmap pour le Reporting Standardisé 
        """
        clean_report = []
        
        # On itère sur tous les hôtes trouvés
        for host in self.nm.all_hosts():
            host_data = {
                "ip": host,
                "status": self.nm[host].state(),
                "hostnames": self.nm[host].hostname(),
                "os_match": [],
                "open_ports": []
            }

            # Récupération de l'OS (si détecté)
            if 'osmatch' in self.nm[host]:
                for os in self.nm[host]['osmatch']:
                    host_data["os_match"].append({
                        "name": os['name'],
                        "accuracy": os['accuracy']
                    })

            # Récupération des ports et services
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in sorted(ports):
                    service = self.nm[host][proto][port]
                    port_info = {
                        "port": port,
                        "protocol": proto,
                        "state": service['state'],
                        "service_name": service['name'],
                        "product": service['product'], # ex: Apache httpd
                        "version": service['version'], # ex: 2.4.49
                        "cpe": service.get('cpe', '')  # Common Platform Enumeration (utile pour chercher des CVE après)
                    }
                    host_data["open_ports"].append(port_info)
            
            clean_report.append(host_data)

        return clean_report

# --- Exemple d'utilisation (Simulation) ---
if __name__ == "__main__":
    scanner = NmapModule()
    # Dans la vraie vie, target viendrait de votre API
    resultat = scanner.run_scan("127.0.0.1", scan_type="full")
    
    # Affichage du JSON propre (ce qui sera stocké en BDD)
    print(json.dumps(resultat, indent=4))