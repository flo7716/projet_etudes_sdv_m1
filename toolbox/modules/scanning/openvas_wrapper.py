from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.errors import GvmError
from toolbox.core.config import settings
import logging

class OpenVASScanner:
    def __init__(self):
        # Configuration de la connexion (ne l'ouvre pas encore)
        self.connection = TLSConnection(
            hostname=settings.OPENVAS_HOST,
            port=settings.OPENVAS_PORT
        )

    def scan(self, target_ip):
        """
        Méthode principale : Orchestre la création et le lancement du scan.
        Utilise 'with Gmp(...)' pour s'assurer que la connexion se ferme proprement.
        """
        try:
            with Gmp(connection=self.connection) as gmp:
                # 1. Authentification
                gmp.authenticate(
                    settings.OPENVAS_USERNAME,
                    settings.OPENVAS_PASSWORD
                )
                logging.info(f"[+] Connecté à OpenVAS pour la cible {target_ip}")

                # 2. Création de la cible
                target_res = gmp.create_target(
                    name=f"target-{target_ip}",
                    hosts=[target_ip]
                )
                target_id = target_res.get("id")

                # 3. Récupération de la bonne configuration (Full and fast)
                # L'UUID 'daba56c8-73ec-11df-a475-002264764cea' est le standard global d'OpenVAS
                config_id = "daba56c8-73ec-11df-a475-002264764cea" 

                # 4. Création de la tâche
                task_res = gmp.create_task(
                    name=f"toolbox-scan-{target_ip}",
                    config_id=config_id,
                    target_id=target_id
                )
                task_id = task_res.get("id")

                # 5. Lancement de la tâche
                gmp.start_task(task_id)
                logging.info(f"[+] Scan OpenVAS démarré. Task ID: {task_id}")

                return task_id

        except GvmError as e:
            logging.error(f"[-] Erreur API OpenVAS: {str(e)}")
            return None
        except Exception as e:
            logging.error(f"[-] Erreur de connexion au conteneur OpenVAS: {str(e)}")
            return None
        
    def get_status(self, task_id):
        """ 
        Vérifie l'état actuel du scan.
        """
        try:
            with Gmp(connection=self.connection) as gmp:
                gmp.authenticate(settings.OPENVAS_USERNAME, settings.OPENVAS_PASSWORD)
                
                # On interroge l'API pour cette tâche précise
                task_res = gmp.get_task(task_id)
                
                # Extraction du statut via XPath (car OpenVAS renvoie du XML)
                status = task_res.xpath('//status/text()')[0]
                progress = task_res.xpath('//progress/text()')[0]
                
                return {"status": status, "progress": progress} # ex: "Running", "85%"
                
        except Exception as e:
            logging.error(f"[-] Erreur de statut OpenVAS: {str(e)}")
            return {"status": "Error", "message": str(e)}

    def get_report(self, task_id):
        """
        Récupère le rapport une fois le scan terminé ('Done') et extrait 
        les vulnérabilités pour les standardiser au format de votre BDD.
        """
        try:
            with Gmp(connection=self.connection) as gmp:
                gmp.authenticate(settings.OPENVAS_USERNAME, settings.OPENVAS_PASSWORD)
                
                # 1. Récupérer l'ID du rapport généré par la tâche
                task_res = gmp.get_task(task_id)
                status = task_res.xpath('//status/text()')[0]
                
                if status != 'Done':
                    return {"error": f"Le scan n'est pas terminé. Statut actuel: {status}"}
                
                report_id = task_res.xpath('//report/@id')[0]
                
                # 2. Demander le rapport au format XML (pour pouvoir le parser)
                # L'UUID 'a994b278-1f62-11e1-96ac-406186ea4fc5' est le format XML standard
                report_format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"
                report_res = gmp.get_report(
                    report_id=report_id, 
                    report_format_id=report_format_id,
                    ignore_pagination=True
                )
                
                # 3. Parsing (Nettoyage) des vulnérabilités
                vulns = []
                # On cherche toutes les balises <result> (les failles trouvées)
                results = report_res.xpath('//report/report/results/result')
                
                for res in results:
                    # On évite de polluer la BDD avec les simples logs ("Log" ou "Debug")
                    threat = res.xpath('threat/text()')[0]
                    if threat not in ['High', 'Medium', 'Low', 'Critical']:
                        continue
                        
                    vulns.append({
                        "tool_source": "OpenVAS",
                        "title": res.xpath('name/text()')[0],
                        "severity": threat.upper(), # CRITICAL, HIGH...
                        "description": res.xpath('description/text()')[0],
                        "port": res.xpath('port/text()')[0],
                        "cve_id": res.xpath('nvt/cve/text()')[0] if res.xpath('nvt/cve/text()') != ['NOCVE'] else None
                    })
                    
                return {
                    "task_id": task_id,
                    "vulnerabilities_found": len(vulns),
                    "details": vulns
                }

        except Exception as e:
            logging.error(f"[-] Erreur de récupération du rapport: {str(e)}")
            return None