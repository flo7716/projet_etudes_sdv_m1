import subprocess
import xml.etree.ElementTree as ET
from app.modules.interactive import prompt_text


def parse_nmap(xml_output):
    root = ET.fromstring(xml_output)
    host = root.find("host")

    addresses = []
    hostnames = []
    status = None
    if host is not None:
        status_el = host.find("status")
        if status_el is not None:
            status = status_el.get("state")

        for address in host.findall("address"):
            addr = address.get("addr")
            if addr:
                addresses.append(addr)

        for hostname in host.findall("hostname"):
            name = hostname.get("name")
            if name:
                hostnames.append(name)

    scan_info = {}
    scan_info_el = root.find("scaninfo")
    if scan_info_el is not None:
        scan_info = scan_info_el.attrib

    os_matches = []
    for osmatch in root.findall(".//osmatch"):
        os_matches.append({
            "name": osmatch.get("name"),
            "accuracy": osmatch.get("accuracy"),
            "line": osmatch.get("line"),
        })

    ports = []
    for port in root.findall(".//port"):
        state_el = port.find("state")
        if state_el is None:
            continue

        state = state_el.get("state")
        service_el = port.find("service")
        service = {}
        if service_el is not None:
            service = {
                "name": service_el.get("name"),
                "product": service_el.get("product"),
                "version": service_el.get("version"),
                "extrainfo": service_el.get("extrainfo"),
            }

        scripts = []
        for script in port.findall("script"):
            scripts.append({
                "id": script.get("id"),
                "output": script.get("output"),
            })

        ports.append({
            "port": port.get("portid"),
            "protocol": port.get("protocol"),
            "state": state,
            "service": service,
            "scripts": scripts,
        })

    open_ports = [p for p in ports if p["state"] == "open"]

    scan_stats = {}
    finished = root.find("runstats/finished")
    if finished is not None:
        scan_stats = finished.attrib

    return {
        "status": status,
        "host": {
            "addresses": addresses,
            "hostnames": hostnames,
        },
        "scan_info": scan_info,
        "scan_stats": scan_stats,
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
        "os_matches": os_matches,
    }


def run_nmap(target, options=""):

    command = [
        "nmap",
        "-sV",
        "-sC",
        "-O",
        "-oX", "-"
    ]

    if options:
        import shlex
        command.extend(shlex.split(options))

    command.append(target)

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    # debug si erreur nmap
    if result.returncode != 0:
        return {
            "error": result.stderr
        }

    try:
        return parse_nmap(result.stdout)

    except ET.ParseError:
        return {
            "error": "Impossible de parser le XML Nmap",
            "raw_output": result.stdout[:500]
        }