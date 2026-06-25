import re
import subprocess
from app.modules.interactive import prompt_text


WEAK_CIPHER_PATTERNS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "CBC"]
DEPRECATED_PROTOCOLS = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]


def parse_sslyze(output):
    findings = []
    lines = [l.strip() for l in output.splitlines() if l.strip()]

    # Certificate trust
    untrusted_stores = set()
    cert_subject = None
    cert_lifespan_issue = None
    deprecated_supported = set()
    weak_ciphers = set()

    for line in lines:
        # "Android CA Store (16.0.0 r4): FAILED - Certificate is NOT Trusted: ..."
        m = re.match(r"^([A-Za-z][\w .()/-]*?CA Store[^:]*):\s*FAILED", line)
        if m:
            untrusted_stores.add(m.group(1).strip())
            cn = re.search(r"CN=([\w.\-]+)", line)
            if cn:
                cert_subject = cn.group(1)
            continue

        if "maximum certificate lifespan" in line.lower() and "should be less than" in line.lower():
            cert_lifespan_issue = line.split("*", 1)[-1].strip()
            continue

        for proto in DEPRECATED_PROTOCOLS:
            if proto.lower() in line.lower() and ("supported" in line.lower() or "cipher suites" in line.lower()):
                # capture lines that explicitly mention supported deprecated protocol
                if "supported" in line.lower():
                    deprecated_supported.add(proto)

        for cipher in WEAK_CIPHER_PATTERNS:
            if cipher in line and "supported" in line.lower() and "should be rejected" in line.lower():
                weak_ciphers.add(cipher)

    if untrusted_stores:
        target_desc = f" (certificate CN={cert_subject})" if cert_subject else ""
        findings.append(
            f"Certificate is not trusted by {len(untrusted_stores)} major trust store(s){target_desc}: "
            + ", ".join(sorted(untrusted_stores))
        )

    if cert_lifespan_issue:
        findings.append(f"Certificate lifespan issue: {cert_lifespan_issue}")

    if deprecated_supported:
        findings.append(
            "Deprecated TLS/SSL protocol version(s) still supported: " + ", ".join(sorted(deprecated_supported))
        )

    if weak_ciphers:
        findings.append(
            "Weak cipher suite families supported (should be rejected): " + ", ".join(sorted(weak_ciphers))
        )

    if not findings:
        findings.append("No major TLS/SSL configuration issues were identified by sslyze.")


    # --- Set severity based on findings ---
    severity = "low"
    if deprecated_supported or weak_ciphers:
        severity = "medium"
    if untrusted_stores or cert_lifespan_issue:
        severity = "high"
        
    return {
        "ssl_issues_count": len(findings),
        "findings": findings,
        "raw_output": output,
        "severity": severity # <--- Inject severity into the returned dictionary
    }


def run_sslyze(target, options=""):

    command = [
        "sslyze",
        target
    ]
    if options:
        command.extend(options.split())

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return parse_sslyze(result.stdout)


def run_sslyze_interactive():
    target = prompt_text(
        "Enter target host:",
        validate=lambda x: len(x) > 0,
    )
    options = prompt_text(
        "Additional sslyze options (leave empty for defaults):",
    )

    return run_sslyze(target, options)