import subprocess
import xml.etree.ElementTree as ET


def parse_nmap(xml_output):

    root = ET.fromstring(xml_output)

    results = []

    for port in root.findall(".//port"):

        state = port.find("state").get("state")

        # garder uniquement ports ouverts
        if state != "open":
            continue

        port_id = port.get("portid")

        service_element = port.find("service")

        service = (
            service_element.get("name")
            if service_element is not None
            else "unknown"
        )

        results.append({
            "port": port_id,
            "service": service
        })

    return {
        "open_ports_count": len(results),
        "open_ports": results
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