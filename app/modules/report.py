import os
import re
import subprocess
import tempfile
import json
from typing import Dict, Any


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


LATEX_TEMPLATE = r"""
\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{margin=1in}
\begin{document}

%s
\end{document}
"""

TEMPLATE_PLACEHOLDER = "%%REPORT_CONTENT%%"
TITLE_PLACEHOLDER = "%%REPORT_TITLE%%"


def _escape_latex(text: str) -> str:
    replacements = {
        "\\": "\\textbackslash{}",
        "%": "\\%",
        "$": "\\$",
        "#": "\\#",
        "&": "\\&",
        "_": "\\_",
        "{": "\\{",
        "}": "\\}",
        "~": "\\textasciitilde{}",
        "^": "\\textasciicircum{}",
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text


def _clean_text(text: str) -> str:
    ansi_escape = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    text = ansi_escape.sub("", text)
    return "".join(ch for ch in text if ch.isprintable() or ch in "\n\r\t")


def _sanitize_data(data: Any) -> Any:
    if isinstance(data, str):
        return _clean_text(data)
    if isinstance(data, dict):
        return {k: _sanitize_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_data(v) for v in data]
    if isinstance(data, tuple):
        return tuple(_sanitize_data(v) for v in data)
    return data


def _extract_text(value: Any) -> str:
    if isinstance(value, str):
        return _clean_text(value)
    if isinstance(value, dict):
        return ", ".join(f"{k}={_extract_text(v)}" for k, v in value.items())
    if isinstance(value, list):
        return " | ".join(_extract_text(item) for item in value if _extract_text(item))
    return str(value)


def normalize_tool_result(tool: str, data: Any, target: str | None = None) -> Dict[str, Any]:
    """Return a standard result object for any tool while preserving existing raw output."""
    if isinstance(data, dict) and data.get("tool") and data.get("summary") and "findings" in data:
        normalized = dict(data)
    else:
        normalized = dict(data) if isinstance(data, dict) else {"raw_output": data}

    normalized.setdefault("tool", tool)
    normalized.setdefault("target", target or (data.get("target") if isinstance(data, dict) else None))
    normalized.setdefault("summary", "")
    normalized.setdefault("findings", [])
    normalized.setdefault("severity", "medium")
    normalized.setdefault("raw_output", data)
    normalized.setdefault("objective", TOOL_OBJECTIVES.get(tool, "Collect evidence and highlight exposure areas."))
    normalized.setdefault("recommendations", [TOOL_RECOMMENDATIONS.get(tool, "Review and remediate the reported findings promptly.")])

    summary = normalized.get("summary") or ""
    if not summary:
        if isinstance(data, dict):
            if data.get("open_ports_count") is not None:
                summary = f"{tool} reported {data.get('open_ports_count', 0)} open port(s)."
            elif data.get("cracked_passwords_count") is not None:
                summary = f"{tool} reported {data.get('cracked_passwords_count', 0)} cracked credential(s)."
            elif data.get("vulnerabilities_count") is not None:
                summary = f"{tool} reported {data.get('vulnerabilities_count', 0)} finding(s)."
            elif data.get("error"):
                summary = f"{tool} failed: {data.get('error')}"
            else:
                summary = f"{tool} completed with the available evidence."
        else:
            summary = f"{tool} completed with the available evidence."
    normalized["summary"] = _clean_text(summary)

    findings = normalized.get("findings") or []
    if not findings:
        if isinstance(data, dict):
            for key in ("findings", "vulnerabilities", "cracked_passwords", "open_ports", "exploits", "issues", "alerts"):
                value = data.get(key)
                if isinstance(value, list) and value:
                    findings = [_extract_text(item) for item in value if _extract_text(item)]
                    break
        if not findings and isinstance(data, dict) and data.get("open_ports_count"):
            findings = [f"Detected {data.get('open_ports_count')} open port(s) during the scan."]
        if not findings and isinstance(data, dict) and data.get("cracked_passwords_count"):
            findings = [f"Recovered {data.get('cracked_passwords_count')} cracked credential(s)."]
        if not findings and isinstance(data, dict) and data.get("vulnerabilities_count"):
            findings = [f"Reported {data.get('vulnerabilities_count')} finding(s)."]
        if not findings and isinstance(data, dict) and data.get("raw_output"):
            findings = [line.strip() for line in str(data.get("raw_output")).splitlines() if line.strip()][:8]
        if not findings and isinstance(data, str):
            findings = [line.strip() for line in data.splitlines() if line.strip()][:8]
    normalized["findings"] = findings or []

    severity = normalized.get("severity") or "medium"
    if severity not in SEVERITY_WEIGHTS:
        severity = "medium"
    normalized["severity"] = severity

    recommendations = normalized.get("recommendations") or [TOOL_RECOMMENDATIONS.get(tool, "Review the findings and apply the corresponding remediation steps.")]
    if isinstance(recommendations, str):
        recommendations = [recommendations]
    normalized["recommendations"] = recommendations

    return _sanitize_data(normalized)


def normalize_results(results: Dict[str, Any]) -> Dict[str, Any]:
    normalized = {}
    for tool, data in results.items():
        normalized[tool] = normalize_tool_result(
            tool,
            data,
            target=(data.get("target") if isinstance(data, dict) else None),
        )
    return normalized


def build_global_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_results(results)
    severity_breakdown = {label: 0 for label in ("low", "medium", "high", "critical")}
    total_findings = 0
    risk_score = 0

    for tool, data in normalized.items():
        severity = data.get("severity", "medium")
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

        findings = data.get("findings") or []
        total_findings += len(findings)
        risk_score += SEVERITY_WEIGHTS.get(severity, 2) * max(1, len(findings))

    recommendations = []
    for tool, data in normalized.items():
        recs = data.get("recommendations") or []
        if isinstance(recs, str):
            recs = [recs]
        recommendations.extend(recs)

    return {
        "total_tools": len(normalized),
        "total_findings": total_findings,
        "severity_breakdown": severity_breakdown,
        "risk_score": min(100, risk_score),
        "recommendations": list(dict.fromkeys(recommendations))[:8],
    }


def _load_report_template() -> str:
    template_path = os.path.join(os.path.dirname(__file__), "model", "report.tex")
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return LATEX_TEMPLATE


def _render_summary_page(results: Dict[str, Any]) -> str:
    normalized = normalize_results(results)
    summary = build_global_summary(normalized)
    tests = sorted(normalized.keys())

    parts = [
        "\\section*{Executive Summary}",
        "\\begin{itemize}",
        f"  \\item \\textbf{{Total vulnerabilities}}: {summary['total_findings']}",
        f"  \\item \\textbf{{Risk score}}: {summary['risk_score']} / 100",
        f"  \\item \\textbf{{Tools executed}}: {summary['total_tools']}",
        "\\end{itemize}",
        "\\paragraph{Severity distribution}\\\n",
        "\\begin{itemize}",
    ]
    for label, count in summary["severity_breakdown"].items():
        if count:
            parts.append(f"  \\item {label.title()}: {count}")
    parts.append("\\end{itemize}")
    parts.append("\\paragraph{Priority recommendations}\\\n")
    parts.append("\\begin{itemize}")
    for recommendation in summary["recommendations"]:
        parts.append(f"  \\item {_escape_latex(str(recommendation))}")
    parts.append("\\end{itemize}")
    parts.append("\\paragraph{Per-tool status}\\\n")
    parts.append("\\begin{itemize}")
    for tool in tests:
        data = normalized[tool]
        status = data.get("summary") or "Completed"
        severity = data.get("severity", "medium")
        parts.append(
            f"  \\item \\textbf{{{_escape_latex(tool)}}}: {_escape_latex(str(status))} (risk: {severity})"
        )
    parts.append("\\end{itemize}")
    return "\n".join(parts)


def _render_verbatim(data: Any) -> str:
    try:
        dump = json.dumps(_sanitize_data(data), ensure_ascii=False, indent=2)
    except Exception:
        dump = repr(_sanitize_data(data))
    return "\\begin{Verbatim}[breaklines=true,fontsize=\\small]\n" + dump + "\n\\end{Verbatim}"


def _render_itemize(data: Any) -> str:
    if isinstance(data, dict):
        lines = ["\\begin{itemize}"]
        for key, value in data.items():
            if isinstance(value, (str, int, float)) or value is None:
                display_value = "" if value is None else str(value)
                lines.append(f"  \\item \\textbf{{{_escape_latex(str(key))}}}: {_escape_latex(display_value)}")
            elif isinstance(value, list) and all(isinstance(item, (str, int, float)) for item in value):
                lines.append(f"  \\item \\textbf{{{_escape_latex(str(key))}}}:")
                lines.append("    \\begin{itemize}")
                for item in value:
                    lines.append(f"      \\item {_escape_latex(str(item))}")
                lines.append("    \\end{itemize}")
            else:
                lines.append(f"  \\item \\textbf{{{_escape_latex(str(key))}}}: {_escape_latex(str(value))}")
        lines.append("\\end{itemize}")
        return "\n".join(lines)
    if isinstance(data, list):
        lines = ["\\begin{itemize}"]
        for item in data:
            lines.append(f"  \\item {_escape_latex(str(item))}")
        lines.append("\\end{itemize}")
        return "\n".join(lines)
    return _render_verbatim(data)


def _format_service_info(service: dict) -> str:
    parts = []
    name = service.get("name")
    if name:
        parts.append(name)
    if service.get("product"):
        parts.append(service["product"])
    if service.get("version"):
        parts.append(service["version"])
    if service.get("extrainfo"):
        parts.append(service["extrainfo"])
    return " ".join(parts).strip()


def _render_nmap_data(data: Dict[str, Any]) -> str:
    parts = []
    host = data.get("host", {})
    if host:
        if host.get("hostnames"):
            parts.append("\\textbf{Hostnames}: " + _escape_latex(", ".join(host["hostnames"])) + "\\")
        if host.get("addresses"):
            parts.append("\\textbf{Addresses}: " + _escape_latex(", ".join(host["addresses"])) + "\\")
    parts.append("\\textbf{Host Status}: " + _escape_latex(str(data.get("status", "unknown"))) + "\\")
    open_ports_count = data.get("open_ports_count", 0)
    parts.append("\\textbf{Open Ports Found}: " + _escape_latex(str(open_ports_count)) + "\\")
    parts.append("\\subsection*{Open ports}")
    if data.get("open_ports"):
        parts.append("\\begin{itemize}")
        for port in data["open_ports"]:
            service = _format_service_info(port.get("service", {}))
            port_label = f"{port.get('port')}/{port.get('protocol')} - {service}".strip()
            parts.append("  \\item " + _escape_latex(port_label))
            scripts = port.get("scripts", [])
            if scripts:
                parts.append("  \\begin{itemize}")
                for script in scripts:
                    script_line = f"{script.get('id')}: {script.get('output')}"
                    parts.append("    \\item " + _escape_latex(script_line))
                parts.append("  \\end{itemize}")
        parts.append("\\end{itemize}")
    else:
        parts.append("No open ports detected.\\")

    os_matches = data.get("os_matches", [])
    if os_matches:
        parts.append("\\subsection*{OS matches}")
        parts.append("\\begin{itemize}")
        for match in os_matches:
            match_line = f"{match.get('name')} (accuracy: {match.get('accuracy')})"
            parts.append("  \\item " + _escape_latex(match_line))
        parts.append("\\end{itemize}")

    return "\n".join(parts)


def _render_tool_page(tool: str, data: Any) -> str:
    normalized = normalize_tool_result(tool, data, target=(data.get("target") if isinstance(data, dict) else None))
    title = f"\\section*{{{_escape_latex(tool.title())}}}"

    if isinstance(normalized, dict) and normalized.get("error"):
        return title + "\n\\textbf{Error}: " + _escape_latex(str(normalized.get("error")))

    sections = [
        "\\subsection*{Objective}",
        _escape_latex(normalized.get("objective") or TOOL_OBJECTIVES.get(tool, "Collect evidence and highlight exposure areas.")) + "\\",
        "\\subsection*{Target}",
        _escape_latex(str(normalized.get("target") or "Not specified")) + "\\",
        "\\subsection*{Executive summary}",
        _escape_latex(str(normalized.get("summary") or "No summary was recorded for this run.")) + "\\",
        "\\subsection*{Main findings}",
    ]

    findings = normalized.get("findings") or []
    if findings:
        sections.append("\\begin{itemize}")
        for item in findings[:12]:
            sections.append(f"  \\item {_escape_latex(str(item))}")
        sections.append("\\end{itemize}")
    else:
        sections.append("No additional findings were captured in the raw output.\\")

    severity = normalized.get("severity", "medium")
    recommendations = normalized.get("recommendations") or []
    if isinstance(recommendations, str):
        recommendations = [recommendations]

    sections.extend([
        "\\subsection*{Risk level}",
        f"{_escape_latex(severity.title())}\\",
        "\\subsection*{Recommendations}",
        "\\begin{itemize}",
    ])
    for recommendation in recommendations[:5]:
        sections.append(f"  \\item {_escape_latex(str(recommendation))}")
    sections.append("\\end{itemize}")

    if tool == "nmap" and isinstance(normalized, dict):
        sections.append("\\subsection*{Network details}")
        sections.append(_render_nmap_data(normalized))

    if isinstance(normalized.get("raw_output"), dict) and normalized["raw_output"].get("raw_output"):
        sections.append("\\subsection*{Raw output}")
        sections.append(_render_verbatim(normalized["raw_output"]))

    return title + "\n" + "\n".join(sections)


def _render_results_as_latex(results: Dict[str, Any]) -> str:
    normalized = normalize_results(results)
    pages = [
        _render_summary_page(normalized),
    ]
    for tool, data in normalized.items():
        pages.append(_render_tool_page(tool, data))
    return "\n\\newpage\n".join(pages)


def _find_host_mount_candidates():
    candidates = [
        os.environ.get("HOST_OUTPUT_DIR"),
        "/host",
        "/host_mnt",
        "/mnt",
        "/app",
        "/workspace",
    ]
    return [c for c in candidates if c]


def _is_mount(path: str) -> bool:
    try:
        return os.path.ismount(path)
    except Exception:
        return False


def generate_pdf_report(results: Dict[str, Any], title: str, output_path: str, copy_to_host: bool = False, host_dest: str | None = None) -> Dict[str, Any]:
    """Generate a PDF report from results using pdflatex. Returns info dict.

    Writes temporary .tex, runs pdflatex, and moves PDF to output_path.
    """
    template = _load_report_template()
    normalized_results = normalize_results(results)
    tex_body = _render_results_as_latex(normalized_results)
    if TEMPLATE_PLACEHOLDER in template:
        tex = template.replace(TEMPLATE_PLACEHOLDER, tex_body)
    elif "\\end{document}" in template:
        tex = template.replace("\\end{document}", tex_body + "\n\\end{document}")
    else:
        tex = LATEX_TEMPLATE % tex_body

    if title and TITLE_PLACEHOLDER in tex:
        tex = tex.replace(TITLE_PLACEHOLDER, _escape_latex(title))
    else:
        # If no placeholder exists, try to inject the title into the template.
        try:
            if title:
                if re.search(r"\\title\s*\{.*?\}", tex, flags=re.S):
                    tex = re.sub(r"\\title\s*\{.*?\}", f"\\title{{{_escape_latex(title)}}}", tex, flags=re.S)
                else:
                    tex = tex.replace(
                        "\\begin{document}",
                        f"\\title{{{_escape_latex(title)}}}\n\\begin{{document}}",
                    )

            if "\\maketitle" in tex and "\\title" in tex and tex.find("\\maketitle") < tex.find("\\title"):
                tex = tex.replace("\\maketitle", "", 1)
                tex = tex.replace("\\begin{document}", "\\begin{document}\n\\maketitle", 1)
        except Exception:
            pass

    # ensure output directory exists
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        tex_path = os.path.join(td, "report.tex")
        with open(tex_path, "w", encoding="utf-8") as f:
            f.write(tex)
        
        # Copy logo to temp directory if it exists
        logo_src = os.path.join(os.path.dirname(__file__), "model", "logo_sdv.jpg")
        if os.path.exists(logo_src):
            import shutil
            logo_dst = os.path.join(td, "logo_sdv.jpg")
            shutil.copy2(logo_src, logo_dst)

        # run pdflatex twice for cross-refs (if any)
        try:
            generated_pdf = os.path.join(td, "report.pdf")
            last_stdout = ""
            last_stderr = ""
            for i in range(2):
                proc = subprocess.run(
                    ["pdflatex", "-interaction=nonstopmode", "report.tex"],
                    cwd=td,
                    capture_output=True,
                    text=True,
                )
                last_stdout = proc.stdout
                last_stderr = proc.stderr

                if proc.returncode != 0:
                    return {
                        "error": "pdflatex failed",
                        "log": proc.stdout + proc.stderr,
                    }
            # move to output path
            try:
                os.replace(generated_pdf, output_path)
            except OSError as e:
                import shutil
                import errno

                if e.errno == errno.EXDEV:
                    shutil.copy2(generated_pdf, output_path)
                    os.remove(generated_pdf)
                else:
                    raise

            info = {"pdf_path": output_path, "pdflatex_stdout": last_stdout, "pdflatex_stderr": last_stderr}

            if copy_to_host:
                import shutil

                if host_dest:
                    try:
                        os.makedirs(host_dest, exist_ok=True)
                        dest = os.path.join(host_dest, os.path.basename(output_path))
                        # if dest is same as output_path, skip copying
                        if os.path.abspath(dest) == os.path.abspath(output_path):
                            info["copied_to_host"] = dest
                        else:
                            shutil.copy2(output_path, dest)
                            info["copied_to_host"] = dest
                    except Exception as e:
                        info["copied_to_host"] = None
                        info["copy_error"] = str(e)
                else:
                    # try to detect host bind mounts and copy the PDF there
                    copied = False
                    for cand in _find_host_mount_candidates():
                        if not cand:
                            continue
                        if _is_mount(cand) or os.path.exists(cand):
                            try:
                                dest = os.path.join(cand, os.path.basename(output_path))
                                # copy (overwrite) the file
                                shutil.copy2(output_path, dest)
                                info["copied_to_host"] = dest
                                copied = True
                                break
                            except Exception:
                                continue

                    if not copied:
                        info["copied_to_host"] = None

            return info

        except FileNotFoundError:
            return {"error": "pdflatex not found"}
        except Exception as e:
            return {"error": str(e)}
