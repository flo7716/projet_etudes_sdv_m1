# app/modules/nmap.py
import subprocess
import xml.etree.ElementTree as ET
import os
import tempfile
import shlex
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
    # Creation of a temporary file for Nmap XML output
    fd, temp_xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    # Modified command: normal output (text) will go to stdout, XML will go to the temporary file
    command = [
        "nmap",
        "-sV",
        "-sC",
        "-O",
        "-oX", temp_xml_path
    ]

    if options:
        command.extend(shlex.split(options))

    command.append(target)

    try:
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
                "summary": "Nmap failed to execute properly.",
                "raw_output": result.stderr
            }

        # Read and parse the XML output from the temporary file
        if os.path.exists(temp_xml_path) and os.path.getsize(temp_xml_path) > 0:
            with open(temp_xml_path, "r", encoding="utf-8", errors="replace") as f:
                xml_content = f.read()
            
            parsed_data = parse_nmap(xml_content)
            
            # CRUCIAL : We inject the raw output of the Nmap command into the parsed data for comprehensive reporting
            parsed_data["raw_output"] = result.stdout
            return parsed_data
        else:
            raise ET.ParseError("XML output file is empty or missing.")

    except ET.ParseError:
        return {
            "error": "Failed to parse Nmap XML payload structures",
            "raw_output": result.stdout[:1000] if result.stdout else "No output stream captured.",
            "findings": ["Error parsing Nmap standard XML structure."],
            "severity": "low",
            "summary": "XML structural anomaly discovered."
        }
    finally:
        # Strict cleanup of the temporary XML file to prevent clutter and potential data leaks
        if os.path.exists(temp_xml_path):
            os.remove(temp_xml_path)

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