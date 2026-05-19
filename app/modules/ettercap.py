import subprocess
import xml.etree.ElementTree as ET

from sympy import root

def parse_ettercap(output):
    root = ET.fromstring(output)

    hosts = []
    for host in root.findall(".//host"):
        ip = host.find("ip").text
        mac = host.find("mac").text if host.find("mac") is not None else "N/A"
        hosts.append({"ip": ip, "mac": mac})

    return {
        "hosts_count": len(hosts),
        "hosts": hosts
    }

def run_ettercap(target, options=""):
    command = [
        "ettercap",
        "-T",
        "-q",
        "-i", "any",
        "-M", f"arp:remote /{target}//"
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_ettercap(result.stdout)