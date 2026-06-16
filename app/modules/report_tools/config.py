# app/modules/report_tools/config.py

# Severity weights used for calculating the global risk score
SEVERITY_WEIGHTS = {"low": 1, "medium": 2, "high": 3, "critical": 4}

TOOL_OBJECTIVES = {
    "nmap": "Identify active hosts, open ports and exposed services.",
    "aircrack_ng": "Assess wireless cracking opportunities and capture-file weaknesses.",
    "sslyze": "Evaluate TLS/SSL configuration, certificates and protocol support.",
    "gobuster": "Enumerate directories and files on the target application.",
    "ffuf": "Probe the target for hidden paths, endpoints and sensitive resources.",
    "nikto": "Detect web server misconfigurations and common vulnerabilities.",
    "nuclei": "Run vulnerability templates against the target.",
    "sqlmap": "Test input parameters for SQL injection and related weaknesses.",
    "hydra": "Verify whether weak credentials can be discovered through brute-force.",
    "john": "Recover or validate password hashes and cracked credentials.",
    "tshark": "Inspect protocol traffic and identify suspicious or exposed data flows.",
    "clamscan": "Scan files or directories for known malware indicators.",
}

TOOL_RECOMMENDATIONS = {
    "nmap": "Close unnecessary services, restrict exposed ports and monitor for unexpected network listeners.",
    "aircrack_ng": "Strengthen wireless protections and require WPA3 or strong passphrase policies.",
    "sslyze": "Disable deprecated protocols, renew certificates and enforce modern TLS settings.",
    "gobuster": "Remove accidental endpoints, enforce authentication and review directory listings.",
    "ffuf": "Harden endpoints, restrict access and fix exposed administrative paths.",
    "nikto": "Patch outdated software, remove default files and secure server headers.",
    "nuclei": "Prioritize template findings and patch the vulnerable components in the exposed stack.",
    "sqlmap": "Use parameterized queries, input validation and application-layer WAF protections.",
    "hydra": "Enforce MFA, strong passwords and account lockout policies.",
    "john": "Rotate cracked credentials and enforce password policies across the environment.",
    "tshark": "Review suspicious flows and restrict unnecessary network exposure.",
    "clamscan": "Quarantine suspicious files and update antivirus signatures regularly.",
}