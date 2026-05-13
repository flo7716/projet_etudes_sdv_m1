import subprocess
import xml.etree.ElementTree as ET


def run_openvas_scan(target):
    result = subprocess.run(["openvas-cli", "scan", target], capture_output=True, text=True)
    return result

def parse_openvas_output(output):
    root = ET.fromstring(output)

    results = []

    for result in root.findall(".//result"):

        port = result.find("port").text
        service = result.find("service").text

        results.append({
            "port": port,
            "service": service
        })

    return {
        "open_ports_count": len(results),
        "open_ports": results
    }


def run_openvas(target):
    result = run_openvas_scan(target)
    output = result.stdout.strip()

    if result.returncode != 0:
        return {
            "error": "OpenVAS scan failed",
            "returncode": result.returncode,
            "stderr": result.stderr.strip(),
            "output": output
        }

    if not output:
        return {
            "message": "OpenVAS scan completed with no output",
            "output": output
        }

    try:
        parsed = parse_openvas_output(output)
        parsed["output"] = output
        return parsed
    except ET.ParseError:
        return {
            "message": "OpenVAS output could not be parsed as XML",
            "output": output
        }
