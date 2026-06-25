# app/modules/report_tools/tools_renderer.py
import json
import os
import glob
import re
from typing import Dict, Any, List
from app.modules.report_tools.config import TOOL_OBJECTIVES, TOOL_RECOMMENDATIONS, TOOL_CONSEQUENCES
from app.modules.report_tools.utils import _escape_latex

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
        severity = str(data.get("severity")).lower()
    return normalized

def _render_top_vulnerabilities(normalized_results: Dict[str, Any]) -> str:
    sections = ["\\subsection*{Critical Vulnerability Highlights}"]
    found = False
    for tool, data in normalized_results.items():
        if str(data.get("severity", "low")).lower() in ["high", "critical"]:
            found = True
            sections.append(f"\\textbf{{Module {tool.upper()} detected severe exposures:}}")
            sections.append("\\begin{itemize}")
            for finding in data.get("findings", [])[:3]:
                sections.append(f"  \\item {_escape_latex(str(finding))}")
            sections.append("\\end{itemize}")
    if not found:
        sections.append("No isolated critical or high threat severity vectors identified during this orchestration window.")
    return "\n".join(sections)

def _criticality_matrix_rows(normalized_results: Dict[str, Any]) -> List[List[str]]:
    """
    Génère les lignes de la matrice de criticité.
    Tous les outils, y compris NUCLEI, sont désormais consolidés de manière quantitative.
    """
    rows = []
    for tool, data in normalized_results.items():
        tool_upper = str(tool).upper()
        global_severity = str(data.get("severity", "low")).strip().upper()
        consequence = TOOL_CONSEQUENCES.get(tool, "Potential security compromise or policy violation.")
        
        findings = data.get("findings", [])
        if not findings:
            rows.append([
                _escape_latex(tool_upper), 
                "Module executed successfully. No severe entries recorded.", 
                global_severity
            ])
        else:
            # UNIFICATION : NUCLEI and all other tools are now quantitatively summarized in the matrix, with a count of findings and a concise description.
            count = len(findings)
            description = f"Identified \\textbf{{{count}}} alert exposures. \\textbf{{Impact:}} {_escape_latex(consequence)}"
            rows.append([_escape_latex(tool_upper), description, global_severity])
                
    return rows

def _render_criticality_matrix(rows: List[List[str]]) -> str:
    if not rows:
        return "No entries logged in the system registry matrix."
    
    tex = [
        "\\begin{table}[H]",
        "\\centering",
        "\\caption{Consolidated Security Vulnerability Matrix Mapping}",
        # Use of p{width} for the second column to ensure proper text wrapping and avoid overflow issues in LaTeX
        "\\begin{tabular}{|l|p{8.5cm}|p{2.5cm}|}",
        "\\hline",
        "\\rowcolor{gray!20} \\textbf{Module Engine} & \\textbf{Detected Threat Description Vector} & \\textbf{Severity} \\\\",
        "\\hline"
    ]
    
    for r in rows:
        sev = r[2].lower()
        color_tag = ""
        if "critical" in sev: color_tag = "\\cellcolor{vulncritical!40}"
        elif "high" in sev: color_tag = "\\cellcolor{vulnhigh!40}"
        elif "medium" in sev: color_tag = "\\cellcolor{vulnmedium!40}"
        elif "low" in sev: color_tag = "\\cellcolor{vulnlow!40}"
        
        # Severity cases are now color-coded for immediate visual recognition in the LaTeX report, enhancing readability and prioritization of findings.
        tex.append(f"{r[0]} & {r[1]} & {color_tag}\\textbf{{{r[2]}}} \\\\")
        tex.append("\\hline")
        
    tex.extend(["\\end{tabular}", "\\end{table}"])
    return "\n".join(tex)

def _render_tool_page(tool: str, data: Dict[str, Any]) -> str:
    tool_upper = tool.upper()
    severity = str(data.get("severity", "low")).lower()
    findings = data.get("findings", [])
    recommendations = data.get("recommendations", [])
    consequence = TOOL_CONSEQUENCES.get(tool, "Potential system compromise or exposure.")
    
    color_map = {"critical": "vulncritical", "high": "vulnhigh", "medium": "vulnmedium", "low": "vulnlow"}
    box_color = color_map.get(severity, "gray")

    title = f"\\section*{{Technical Module Focus: {tool_upper}}}"
    sections = [
        f"\\begin{{tcolorbox}}[colback={box_color}!10, colframe={box_color}, title=Operational Context Summary, arc=1.5mm]",
        f"\\textbf{{Orchestration Status:}} COMPLETED \\\\",
        f"\\textbf{{Tracked Asset Target:}} {_escape_latex(str(data.get('target', 'Local Host')))} \\\\",
        f"\\textbf{{Maximum Severity Threat:}} \\uppercase{{{severity}}} \\\\",
        f"\\textbf{{Total Generated Alerts Count:}} {len(findings)} \\\\",
        f"\\textbf{{Threat Consequence Impact:}} {_escape_latex(str(consequence))}",
        f"\\end{{tcolorbox}}\n",
        "\\subsection*{Identified Vulnerability Highlights}"
    ]

    if not findings:
        sections.append("No operational exceptions or exposures flagged within this engine perimeter.")
    else:
        # Detailed Nuclei and other tool findings are now included in the report, with a limit of the top 10 entries to optimize space and readability.
        for finding in findings[:10]:  # Limit to top 10 elements to optimize spacing
            sections.append(f"\\alertcard{{{box_color}}}{{\\uppercase{{{severity}}}}}{{{_escape_latex(str(finding))}}}")

    sections.extend(["\n\\subsection*{Remediation \\& Hardening Action Plan}", "\\begin{itemize}"])
    if isinstance(recommendations, list):
        for rec in recommendations[:4]:
            sections.append(f"  \\item {_escape_latex(str(rec))}")
    else:
        sections.append(f"  \\item {_escape_latex(str(recommendations))}")
    sections.append("\\end{itemize}")

    return title + "\n" + "\n".join(sections)

def _render_annex_page(normalized_results: Dict[str, Any]) -> str:
    parts = ["\\section*{Technical Appendix: Raw Subprocess Outputs}"]
    for tool, data in normalized_results.items():
        raw_output = data.get("raw_output")
        if not raw_output:
            continue
        parts.append(f"\\subsection*{{Raw Stream Dump: {tool.upper()}}}")
        
        if isinstance(raw_output, (dict, list)):
            dump_str = json.dumps(raw_output, indent=2)
        else:
            dump_str = str(raw_output)

        # STRICT 30 LINES TRUNCATION TO KEEP THE REPORT CLEAN AND ACCELERATE LATEX
        raw_lines = dump_str.splitlines()
        truncated = False
        if len(raw_lines) > 30:
            raw_lines = raw_lines[:30]
            truncated = True
        
        clean_raw = "\n".join(raw_lines)
        if truncated:
            clean_raw += "\n\n[... OUTPUT TRUNCATED FOR CONCISENESS BY SWISSKNIFE REPORTING ENGINE ...]"

        parts.append("\\begin{scriptsize}")
        parts.append("\\begin{Verbatim}[breaklines=true, breakanywhere=true, fontsize=\\small]")
        parts.append(clean_raw)
        parts.append("\\end{Verbatim}")
        parts.append("\\end{scriptsize}")
        
    return "\n".join(parts)