import requests
from toolbox.modules.base import BaseModule


class NessusScanner(BaseModule):

    def execute(self):

        base_url = "https://nessus:8834"
        headers = {
            "X-ApiKeys": "accessKey=xxx; secretKey=yyy"
        }

        data = {
            "uuid": "scan-template-uuid",
            "settings": {
                "name": "scan",
                "text_targets": self.target
            }
        }

        response = requests.post(
            f"{base_url}/scans",
            headers=headers,
            json=data,
            verify=False
        )

        return response.json()