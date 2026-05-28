import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text

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


def run_ettercap_interactive():
    target = prompt_text(
        "Enter target host/IP range (e.g., 192.168.1.0/24):",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional ettercap options (leave empty for defaults):",
        default="",
    )
    print(f"\nRunning ettercap on {target}...")
    return run_ettercap(target, options)