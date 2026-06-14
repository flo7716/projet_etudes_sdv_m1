import re
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
        "raw_output": output[:3000],
    }


def run_tshark(target, options=""):
    command = ["tshark", "-r", target]
    if options:
        command.extend(options.split())

    result = subprocess.run(command, capture_output=True, text=True)
    return parse_tshark(result.stdout)


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