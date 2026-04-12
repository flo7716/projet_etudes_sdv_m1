import subprocess
from toolbox.modules.base import BaseModule


class NmapScanner(BaseModule):

    def execute(self):

        command = [
            "nmap",
            "-sV",
            "-oX", "-",
            self.target
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        return result.stdout