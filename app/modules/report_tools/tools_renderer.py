# app/modules/report_tools/tools_renderer.py
import json
from typing import Any, Dict, List
from .config import SEVERITY_WEIGHTS, TOOL_OBJECTIVES, TOOL_RECOMMENDATIONS
from .utils import _escape_latex

def normalize_tool_result(tool: str, data: Any, target: str | None = None) -> Dict[str, Any]:
    if isinstance(data, dict) and data.get("tool") and "findings" in data:
        normalized = dict(data)
    else:
        normalized = dict(data) if isinstance(data, dict) else {"raw_output": data}

    normalized.setdefault("tool", tool)
    normalized.setdefault("target", target or (data.get("target") if isinstance(data, dict) else None))
    normalized.setdefault("summary", "Execution completed successfully.")
    normalized.setdefault("findings", [])
    normalized.setdefault("raw_output", data)
    normalized.setdefault("objective", TOOL_OBJECTIVES.get(tool, "Collect evidence and highlight exposure areas."))
    normalized.setdefault("recommendations", [TOOL_RECOMMENDATIONS.get(tool, "Review and remediate the reported findings promptly.")])

    severity = "low"
    if isinstance(data, dict) and data.get("severity"):
        severity = data.get("severity").lower()
    return normalized

def _render_top_vulnerabilities(normalized_results: Dict[str, Any]) -> str:
    sections = ["\\subsection*{Critical Vulnerability Highlights}"]
    found = False
    for tool, data in normalized_results.items():
        if data.get("severity") in ["high", "critical"]:
            found = True
            sections.append(f"\\textbf{{[{data['severity'].upper()}] Module {tool.upper()}}}: {data.get('summary')}\\\\")
    if not found:
        sections.append("No critical or high severity vulnerabilities were detected during this pipeline execution.")
    return "\n".join(sections)

def _criticality_matrix_rows(normalized_results: Dict[str, Any]) -> List[Dict[str, str]]:
    rows = []
    for tool, data in normalized_results.items():
        findings = data.get("findings") or []
        severity = data.get("severity", "low")
        if not findings:
            rows.append({"tool": tool.upper(), "finding": "No critical anomalies discovered.", "severity": severity})
        else:
            for finding in findings:
                rows.append({"tool": tool.upper(), "finding": str(finding), "severity": severity})
    return rows

def _render_criticality_matrix(matrix_rows: List[Dict[str, str]]) -> str:
    if not matrix_rows:
        return ""
    parts = [
        "\\subsection*{Identified Vulnerabilities Matrix}",
        "\\begin{table}[H]",
        "\\centering",
        "\\begin{tabular}{|l|p{9cm}|c|}",
        "\\hline",
        "\\textbf{Module} & \\textbf{Detected Threat / Vulnerability Description} & \\textbf{Severity} \\\\",
        "\\hline"
    ]
    
    color_map = {
        "critical": "vuln_critical",
        "high": "vuln_high",
        "medium": "vuln_medium",
        "weak": "vuln_medium",
        "low": "vuln_low"
    }

    for row in matrix_rows:
        tool = _escape_latex(row.get("tool", "UNKNOWN"))
        finding = _escape_latex(row.get("finding", ""))
        severity = row.get("severity", "low").lower()
        
        color = color_map.get(severity, "white")
        parts.append(f"{tool} & {finding} & \\cellcolor{{{color}}}\\textbf{{{severity.upper()}}} \\\\")
        parts.append("\\hline")
        
    parts.append("\\end{tabular}")
    parts.append("\\caption{Comprehensive security matrix across active modules}")
    parts.append("\\end{table}")
    return "\n".join(parts)

def render_nmap_data(normalized: Dict[str, Any]) -> str:
    lines = ["\\begin{itemize}"]
    lines.append(f"  \\item Status: {_escape_latex(str(normalized.get('raw_output', {}).get('status', 'unknown')))}")
    lines.append(f"  \\item Total open ports: {normalized.get('raw_output', {}).get('open_ports_count', 0)}")
    lines.append("\\end{itemize}")
    return "\n".join(lines)

def _render_tool_page(tool: str, normalized: Dict[str, Any]) -> str:
    severity = normalized.get("severity", "low").lower()
    recommendations = normalized.get("recommendations", [])
    
    title = f"\\section{{Module Audit Report: {tool.upper()}}}"
    sections = [
        "\\subsection*{Operational Module Objective}",
        _escape_latex(normalized.get("objective", "")),
        "\\subsection*{Technical Summary}",
        _escape_latex(normalized.get("summary", "")),
        "\\subsection*{Expected Threat Impact Analysis}",
        "\\begin{itemize}"
    ]
    
    if severity == "critical":
        sections.append("  \\item Critical Threat Level: Immediate risk of unauthenticated Remote Code Execution (RCE) or total database breach.")
    elif severity == "high":
        sections.append("  \\item High Threat Level: Significant business exposure, data exfiltration potential or corporate identity theft risk.")
    elif severity == "medium":
        sections.append("  \\item Medium Threat Level: Software version disclosure or configuration leak requiring prompt patch scheduling.")
    else:
        sections.append("  \\item Low Threat Level: Minimum direct exploit risk. Hardening advisory.")
    sections.append("\\end{itemize}")

    sections.extend(["\\subsection*{Remediation & Hardening Action Plan}", "\\begin{itemize}"])
    for rec in recommendations[:5]:
        sections.append(f"  \\item {_escape_latex(str(rec))}")
    sections.append("\\end{itemize}")
    
    sections.extend([
        "\\subsection*{Calculated Asset Risk Level}",
        f"Assigned Level: \\textbf{{{severity.upper()}}}\\\\"
    ])

    if tool.lower() == "nmap":
        sections.append("\\subsection*{Network Specific Metrics}")
        sections.append(render_nmap_data(normalized))

    return title + "\n" + "\n".join(sections)

def _render_annex_page(normalized_results: Dict[str, Any]) -> str:
    parts = ["\\section*{Technical Appendix: Raw Structural Output Data}"]
    for tool, data in normalized_results.items():
        raw_output = data.get("raw_output")
        if not raw_output:
            continue
        parts.append(f"\\subsection*{{Module: {tool.upper()}}}")
        parts.append("\\begin{verbatim}")
        if isinstance(raw_output, (dict, list)):
            parts.append(json.dumps(raw_output, indent=2)[:2000])
        else:
            parts.append(str(raw_output)[:2000])
        parts.append("\\end{verbatim}")
    return "\n".join(parts)