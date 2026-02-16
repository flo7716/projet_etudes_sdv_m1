from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from toolbox.core.config import settings


class OpenVASScanner:

    def __init__(self):
        self.connection = TLSConnection(
            hostname=settings.OPENVAS_HOST,
            port=settings.OPENVAS_PORT
        )

    def authenticate(self):

        self.gmp = Gmp(self.connection)
        self.gmp.authenticate(
            settings.OPENVAS_USERNAME,
            settings.OPENVAS_PASSWORD
        )

    def create_target(self, target_ip):

        response = self.gmp.create_target(
            name=f"target-{target_ip}",
            hosts=[target_ip]
        )

        return response.get("id")

    def create_task(self, target_id):

        configs = self.gmp.get_scan_configs()
        config_id = configs[0].get("id")

        task = self.gmp.create_task(
            name="toolbox-scan",
            config_id=config_id,
            target_id=target_id
        )

        return task.get("id")

    def start_scan(self, task_id):

        return self.gmp.start_task(task_id)

    def scan(self, target_ip):

        self.authenticate()

        target_id = self.create_target(target_ip)
        task_id = self.create_task(target_id)

        self.start_scan(task_id)

        return task_id
