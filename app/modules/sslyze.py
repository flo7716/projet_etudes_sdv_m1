# app/modules/sslyze.py
import os
import re
import subprocess
from datetime import datetime
from app.modules.interactive import prompt_text

WEAK_CIPHER_PATTERNS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "CBC"]
DEPRECATED_PROTOCOLS = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]

def parse_sslyze(output: str):
    # Standardize whitespace and remove unnecessary double line-breaks to make the output clear
    cleaned_lines = []
    for line in output.splitlines():
        # Strip trailing whitespaces but preserve original structural indentation
        stripped_line = line.rstrip()
        if stripped_line:
            cleaned_lines.append(stripped_line)
        elif cleaned_lines and cleaned_lines[-1] != "":
            # Keep a single clean empty line instead of consecutive ones
            cleaned_lines.append("")

    # Join lines to re-assemble a beautiful, coherent string
    readable_raw_output = "\n".join(cleaned_lines)

    findings = []
    untrusted_stores = set()
    deprecated_supported = set()
    weak_ciphers = set()
    cert_lifespan_issue = None

    # Parsing engine for structured values
    for line in cleaned_lines:
        line_str = line.strip()
        
        # Identify Trust Store Validation Failures
        if "FAILED - Certificate is NOT Trusted" in line_str:
            m = re.match(r"^([A-Za-z][\w .()/-]*?CA Store[^:]*):", line_str)
            if m:
                untrusted_stores.add(m.group(1).strip())
            continue

        # Certificate lifespan thresholds
        if "maximum certificate lifespan" in line_str.lower() and "should be less than" in line_str.lower():
            if "*" in line_str:
                cert_lifespan_issue = line_str.split("*", 1)[-1].strip()
            continue

        # Enumerate deprecated security communication protocols
        for proto in DEPRECATED_PROTOCOLS:
            if proto.lower() in line_str.lower() and "accepted" in line_str.lower():
                deprecated_supported.add(proto)

        # Enumerate weak cryptographic cipher suites running on target
        for pattern in WEAK_CIPHER_PATTERNS:
            if pattern in line_str and "TLS_" in line_str:
                weak_ciphers.add(pattern)

    # Compile structured analysis lists
    if untrusted_stores:
        findings.append(
            f"Certificate is not trusted by {len(untrusted_stores)} major trust store(s): "
            f"{', '.join(sorted(untrusted_stores))}"
        )
    if cert_lifespan_issue:
        findings.append(f"Certificate lifespan issue: {cert_lifespan_issue}")
    if deprecated_supported:
        findings.append(f"Deprecated TLS/SSL protocol version(s) still supported: {', '.join(sorted(deprecated_supported))}")
    if weak_ciphers:
        findings.append(f"Weak cipher suite families supported (should be rejected): {', '.join(sorted(weak_ciphers))}")

    if not findings:
        findings.append("No major TLS/SSL configuration issues were identified by sslyze.")

    # Calculate defensive threat severity classification
    severity = "low"
    if deprecated_supported or weak_ciphers:
        severity = "medium"
    if untrusted_stores or cert_lifespan_issue:
        severity = "high"

    return {
        "ssl_issues_count": len(findings),
        "findings": findings,
        "raw_output": readable_raw_output,
        "severity": severity,
        "summary": f"TLS protocol assessment completed. Discovered {len(findings)} configuration issues.",
        "tool": "sslyze"
    }

def run_sslyze(target: str, options: str = ""):
    command = ["sslyze", target]
    if options:
        command.extend(options.split())

    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    output = "\n".join(filter(None, [result.stdout, result.stderr]))
    
    scan_results = parse_sslyze(output)

    # Sanitize hostname for filesystem storage directory creation
    clean_hostname = re.sub(r'[^a-zA-Z0-9.\-]', '_', target.replace("http://", "").replace("https://", "").split('/')[0])
    # Check for environment variable override for timestamp before creating new one. If environment exists, use it; otherwise, generate a new timestamp.
    timestamp = os.environ.get("SWISSKNIFE_SCAN_TIMESTAMP", datetime.now().strftime("%Y%m%d_%H%M%S"))
    
    # Compute persistent dynamic path format: results_hostname_timestamp/tool_outputs
    output_dir = os.path.join(f"results_{clean_hostname}_{timestamp}", "tool_outputs")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    persistent_path = os.path.join(output_dir, "sslyze_raw_output.txt")
    with open(persistent_path, "w", encoding="utf-8") as f:
        f.write(scan_results["raw_output"])

    return scan_results

def run_sslyze_interactive():
    target = prompt_text(
        "Enter target host:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional sslyze options (leave empty for defaults):",
        default="",
    )
    print(f"\n▶ Starting SSLyze cryptographic configuration scan on {target}...")
    return run_sslyze(target, options)