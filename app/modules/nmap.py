# app/modules/nmap.py
import subprocess
import xml.etree.ElementTree as ET
import os
import tempfile
import shlex
import re
from datetime import datetime
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

        for hostname in host.findall(".//hostname"):
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
        service_name = service_el.get("name") if service_el is not None else "unknown"
        service_product = service_el.get("product") if service_el is not None else ""
        service_version = service_el.get("version") if service_el is not None else ""

        ports.append({
            "portid": port.get("portid"),
            "protocol": port.get("protocol"),
            "state": state,
            "service": service_name,
            "product": service_product,
            "version": service_version,
        })

    severity = "low"
    findings = []
    open_ports = [p for p in ports if p["state"] == "open"]
    
    for p in open_ports:
        findings.append(f"Port {p['portid']}/{p['protocol']} is OPEN ({p['service']})")
        # Elevate threat severity calculation if remote administration entries are detected
        if p["service"] in ["ssh", "telnet", "ftp", "rdp", "vnc", "smb"]:
            severity = "medium"

    return {
        "tool": "nmap",
        "status": status,
        "addresses": addresses,
        "hostnames": hostnames,
        "scan_info": scan_info,
        "os_matches": os_matches,
        "ports": ports,
        "findings": findings,
        "severity": severity,
        "summary": f"Scan completed. Found {len(open_ports)} open network port(s)."
    }

def run_nmap(target, options=""):
    # Generate unique absolute path secure file handle pointers
    fd, temp_xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    command = ["nmap", "-oX", temp_xml_path, target]
    if options:
        command.extend(shlex.split(options))

    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace")
        
        if result.returncode != 0 and not os.path.exists(temp_xml_path):
            return {
                "error": "Nmap execution anomaly detected",
                "raw_output": result.stderr or result.stdout,
                "findings": ["Process executed with non-zero exit code status descriptor."],
                "severity": "low",
                "summary": "Execution engine fault context."
            }

        if os.path.exists(temp_xml_path) and os.path.getsize(temp_xml_path) > 0:
            with open(temp_xml_path, "r", encoding="utf-8", errors="replace") as f:
                xml_content = f.read()
            
            parsed_data = parse_nmap(xml_content)
            parsed_data["raw_output"] = result.stdout if result.stdout else xml_content
            
            # Sanitize hostname for filesystem storage directory creation
            clean_hostname = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").split('/')[0])
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Compute persistent dynamic path format: results_hostname_timestamp/tool_output
            output_dir = os.path.join(f"results_{clean_hostname}_{timestamp}", "tool_outputs")
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            persistent_path = os.path.join(output_dir, "nmap_raw_output.txt")
            with open(persistent_path, "w", encoding="utf-8") as f:
                f.write(parsed_data["raw_output"])
                
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
    print(f"\n▶ Starting Nmap network reconnaissance scan on {target}...")
    return run_nmap(target, options)