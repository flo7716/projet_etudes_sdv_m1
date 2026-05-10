import subprocess
import xml.etree.ElementTree as ET


def parse_nmap(xml_output):

    root = ET.fromstring(xml_output)

    results = []

    for port in root.findall(".//port"):
        port_id = port.get("portid")
        state = port.find("state").get("state")
        service = port.find("service").get("name")

        results.append({
            "port": port_id,
            "state": state,
            "service": service
        })

    return results

def run_nmap(target):

    command = [
        "nmap",
        "-sV",
        "-sC",
        "-O",
        "-oX", "-",   # sortie XML
        target
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_nmap(result.stdout)