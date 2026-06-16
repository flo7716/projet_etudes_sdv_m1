# app/modules/nmap.py
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

        ports.append({
            "portid": port.get("portid"),
            "protocol": port.get("protocol"),
            "state": state,
            "service": service,
        })

    open_ports = [p for p in ports if p["state"] == "open"]
    findings = [f"Port {p['portid']}/{p['protocol']} is OPEN running service {p['service'].get('name', 'unknown')}" for p in open_ports]

    return {
        "tool": "nmap",
        "status": status,
        "addresses": addresses,
        "hostnames": hostnames,
        "scan_info": scan_info,
        "os_matches": os_matches,
        "open_ports_count": len(open_ports),
        "findings": findings,
        "severity": "medium" if len(open_ports) > 5 else "low",
        "summary": f"Network scan discovered {len(open_ports)} exposed active network ports on the target infrastructure."
    }

def run_nmap(target, options=None):
    command = [
        "nmap",
        "-sV",
        "-sC",
        "-O",
        "-oX", "-"  # Output XML data directly to stdout for immediate dynamic parsing
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

    if result.returncode != 0:
        return {
            "error": result.stderr,
            "findings": [f"Error during network scanning execution: {result.stderr[:100]}"],
            "severity": "low",
            "summary": "Nmap failed to execute properly."
        }

    try:
        return parse_nmap(result.stdout)
    except ET.ParseError:
        return {
            "error": "Failed to parse Nmap XML payload structures",
            "raw_output": result.stdout[:500],
            "findings": ["Error parsing Nmap standard XML structure."],
            "severity": "low",
            "summary": "XML structural anomaly discovered."
        }

def run_nmap_interactive():
    target = prompt_text(
        "Enter target host/IP:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional nmap options (leave empty for defaults):",
        default="",
    )
    return run_nmap(target, options)