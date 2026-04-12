import requests
from toolbox.modules.base import BaseModule


class BurpScanner(BaseModule):

    def execute(self):

        url = f"http://burp:1337/v0.1/scan"

        payload = {
            "urls": [f"http://{self.target}"]
        }

        response = requests.post(url, json=payload)

        return response.json()