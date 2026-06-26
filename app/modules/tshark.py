import re, os, subprocess
from datetime import datetime
import subprocess
from collections import Counter

from app.modules.interactive import prompt_text


def parse_tshark(output: str):
    findings = []
    proto_counter: Counter = Counter()
    ip_counter: Counter = Counter()

    # tshark text output line example:
    #   1 0.000000000 192.168.1.1 -> 192.168.1.2 TCP 74 443->12345 [SYN] Seq=0 Win=64240 Len=0
    line_pattern = re.compile(
        r"^\s*\d+\s+[\d.]+\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)\s+(?P<proto>\S+)\s+(?P<rest>.*)$"
    )

    total_lines = 0
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        total_lines += 1
        m = line_pattern.match(line)
        if m:
            proto = m.group("proto").upper()
            src = m.group("src")
            dst = m.group("dst")
            proto_counter[proto] += 1
            ip_counter[src] += 1
            ip_counter[dst] += 1

    # Build summary findings
    if proto_counter:
        top_protos = ", ".join(
            f"{proto} ({count})" for proto, count in proto_counter.most_common(8)
        )
        findings.append(f"Protocol distribution across {total_lines} packets: {top_protos}")

    if ip_counter:
        top_ips = ip_counter.most_common(5)
        findings.append(
            "Most active IP addresses: "
            + ", ".join(f"{ip} ({count} packets)" for ip, count in top_ips)
        )

    # Flag potentially interesting traffic
    http_count = proto_counter.get("HTTP", 0)
    if http_count:
        findings.append(f"Unencrypted HTTP traffic detected: {http_count} packet(s).")

    dns_count = proto_counter.get("DNS", 0)
    if dns_count:
        findings.append(f"DNS traffic observed: {dns_count} packet(s).")

    tcp_count = proto_counter.get("TCP", 0)
    udp_count = proto_counter.get("UDP", 0)
    if tcp_count or udp_count:
        findings.append(f"Transport layer: TCP={tcp_count} packet(s), UDP={udp_count} packet(s).")

    if not findings:
        findings.append("No notable traffic patterns identified from the capture file.")

    return {
        "packet_count": total_lines,
        "findings_count": len(findings),
        "findings": findings,
        "raw_output": output,
    }




def run_tshark(target, options=""):
    command = ["tshark", "-r", target]
    if options:
        command.extend(options.split())

    result = subprocess.run(command, capture_output=True, text=True)
    scan_results = parse_tshark(result.stdout)

    # Sanitize hostname/URL for filesystem storage directory creation
    clean_filename= re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").split('/')[0])
    # Check for environment variable override for timestamp before creating new one. If environment exists, use it; otherwise, generate a new timestamp and export it.
    timestamp = os.environ.get("SWISSKNIFE_SCAN_TIMESTAMP")
    if not timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.environ["SWISSKNIFE_SCAN_TIMESTAMP"] = timestamp
    
    # Compute persistent dynamic path format: results_hostname_timestamp/tool_output
    output_dir = os.path.join(f"results_{clean_filename}_{timestamp}", "tool_outputs")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    persistent_path = os.path.join(output_dir, "tshark_standalone_raw_output.txt")
    with open(persistent_path, "w", encoding="utf-8") as f:
        f.write(scan_results["raw_output"])

    return scan_results


def run_tshark_interactive():
    target = prompt_text(
        "Enter path to pcap file:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional tshark options (leave empty for defaults):",
        default="",
    )
    return run_tshark(target, options)