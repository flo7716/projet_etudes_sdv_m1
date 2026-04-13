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