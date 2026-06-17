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
        severity = str(data.get("severity")).lower()
    return normalized

def _render_top_vulnerabilities(normalized_results: Dict[str, Any]) -> str:
    sections = ["\\subsection*{Critical Vulnerability Highlights}"]
    found = False
    for tool, data in normalized_results.items():
        if str(data.get("severity", "low")).lower() in ["high", "critical"]:
            found = True
            findings = data.get("findings", [])
            sections.append(f"\\textbf{{Module {tool.upper()}}} detected severe exposures:")
            sections.append("\\begin{itemize}")
            for finding in findings:
                # Échappement de sécurité contre les esperluettes et caractères LaTeX
                sections.append(f"  \\item {_escape_latex(finding)}")
            sections.append("\\end{itemize}")
    if not found:
        sections.append("No isolated critical or high-severity vulnerabilities required immediate out-of-band patching windows.")
    return "\n".join(sections)

def _criticality_matrix_rows(normalized_results: Dict[str, Any]) -> List[List[str]]:
    rows = []
    for tool, data in normalized_results.items():
        findings = data.get("findings", [])
        severity = str(data.get("severity", "low")).upper()
        
        if not findings:
            rows.append([
                _escape_latex(tool.upper()),
                f"Module executed successfully. No severe vulnerabilities discovered.",
                severity
            ])
        else:
            for finding in findings:
                rows.append([
                    _escape_latex(tool.upper()),
                    _escape_latex(finding), # CORRECTION ICI : Échappement obligatoire du finding pour éviter le crash du '&'
                    severity
                ])
    return rows

def _criticality_matrix_rows(normalized_results: Dict[str, Any]) -> List[List[str]]:
    rows = []
    for tool, data in normalized_results.items():
        findings = data.get("findings", [])
        global_severity = str(data.get("severity", "low")).strip().upper()
        tool_upper = str(tool).upper()
        
        if not findings:
            rows.append([
                _escape_latex(tool_upper),
                f"Module executed successfully. No severe vulnerabilities discovered.",
                global_severity
            ])
        else:
            for finding in findings:
                finding_str = str(finding)
                
                # TRAITEMENT SPÉCIFIQUE ET PARSING INDIVIDUEL DE NUCLEI
                if tool_upper == "NUCLEI":
                    # On détermine dynamiquement la sévérité de LA ligne
                    if "[critical]" in finding_str.lower() or "severity: critical" in finding_str.lower():
                        row_severity = "CRITICAL"
                    elif "[high]" in finding_str.lower() or "severity: high" in finding_str.lower():
                        row_severity = "HIGH"
                    elif "[medium]" in finding_str.lower() or "severity: medium" in finding_str.lower():
                        row_severity = "MEDIUM"
                    else:
                        row_severity = "LOW"
                        
                    # Nettoyage de la description si le suffixe "-> Severity:" est présent
                    clean_finding = finding_str.split(" -> Severity:")[0]
                    
                    # On injecte la structure exacte attendue (Liste de 3 éléments)
                    rows.append([
                        _escape_latex("NUCLEI"), # Toujours NUCLEI (pas de NUCLEI_1)
                        _escape_latex(clean_finding), 
                        row_severity # Vraie sévérité de la vulnérabilité !
                    ])
                else:
                    # Comportement normal pour tous les autres modules (Nmap, Sqlmap...)
                    rows.append([
                        _escape_latex(tool_upper),
                        _escape_latex(finding_str), 
                        global_severity
                    ])
    return rows

def _render_criticality_matrix(rows: List[List[str]]) -> str:
    if not rows:
        return ""
    
    tex = [
        "\\subsection*{Consolidated Operational Criticality Matrix}",
        "\\noindent\\begin{tabular}{|l|p{9.5cm}|l|}",
        "\\hline",
        "\\cellcolor{gray!20}\\textbf{Module Source} & \\cellcolor{gray!20}\\textbf{Target Vulnerability / Vector Description} & \\cellcolor{gray!20}\\textbf{Severity} \\\\",
        "\\hline"
    ]
    
    for row in rows:
        mod, desc, sev = row[0], row[1], row[2]
        sev_lower = sev.lower()
        
        cell_color = "vulnlow"
        if sev_lower == "critical": cell_color = "vulncritical"
        elif sev_lower == "high": cell_color = "vulnhigh"
        elif sev_lower in ["medium", "weak"]: cell_color = "vulnmedium"
        
        # --- CORRECTIF SÉCURITÉ DE RETOUR À LA LIGNE ---
        # Si la description est une ligne brute d'outil (comme Nuclei) très longue,
        # on s'assure qu'elle n'excède pas une taille raisonnable pour l'affichage de la cellule
        if len(desc) > 120:
            desc = desc[:117] + "..."
            
        # Échappement obligatoire des caractères spéciaux LaTeX pour empêcher les crashs de compilation
        clean_desc = _escape_latex(desc)
        
        tex.append(f"{mod} & {clean_desc} & \\cellcolor{{{cell_color}}}\\textbf{{{sev}}} \\\\")
        tex.append("\\hline")
        
    tex.append("\\end{tabular}")
    return "\n".join(tex)

def _render_tool_page(tool: str, normalized: Dict[str, Any]) -> str:
    title = f"\\section{{Module Evaluation Report: {tool.upper()}}}"
    objective = normalized.get("objective", "")
    summary = normalized.get("summary", "")
    findings = normalized.get("findings", [])
    recommendations = normalized.get("recommendations", [])
    severity = str(normalized.get("severity", "low")).lower()

    sections = [
        "\\subsection*{Module Objective}",
        _escape_latex(objective),
        "\\subsection*{Operational Executive Summary}",
        _escape_latex(summary),
        "\\subsection*{Detailed Technical Findings}",
        "\\begin{itemize}"
    ]

    if findings:
        for finding in findings:
            sections.append(f"  \\item {_escape_latex(finding)}")
    else:
        sections.append("  \\item No structural anomalies or misconfigurations detected by this tool module.")
    sections.append("\\end{itemize}")

    sections.append("\\subsection*{Target Assessment Analysis}")
    sections.append("\\begin{itemize}")
    if severity == "critical":
        sections.append("  \\item Critical Threat Vector: Immediate threat exploitation capability verified.")
    elif severity == "high":
        sections.append("  \\item High Threat Level: Significant risk of data exposure or application compromise.")
    elif severity == "medium":
        sections.append("  \\item Medium Threat Level: Exposure of internal configurations or sensitive properties.")
    else:
        sections.append("  \\item Low Threat Level: Minimum direct exploit risk. Hardening advisory.")
    sections.append("\\end{itemize}")

    sections.extend(["\\subsection*{Remediation \\& Hardening Action Plan}", "\\begin{itemize}"])
    if isinstance(recommendations, list):
        for rec in recommendations[:5]:
            sections.append(f"  \\item {_escape_latex(rec)}")
    else:
        sections.append(f"  \\item {_escape_latex(recommendations)}")
    sections.append("\\end{itemize}")
    
    sections.extend([
        "\\subsection*{Calculated Asset Risk Level}",
        f"Assigned Level: \\\\textbf{{{_escape_latex(severity.upper())}}}\\\\\\\\"
    ])

    return title + "\n" + "\n".join(sections)

def _render_annex_page(normalized_results: Dict[str, Any]) -> str:
    parts = ["\\section*{Technical Appendix: Raw Structural Output Data}"]
    for tool, data in normalized_results.items():
        raw_output = data.get("raw_output")
        if not raw_output:
            continue
        parts.append(f"\\subsection*{{Module: {tool.upper()}}}")
        
        # --- CORRECTIF : Utilisation de Verbatim avec coupure automatique des lignes ---
        parts.append("\\begin{Verbatim}[breaklines=true, breakanywhere=true, fontsize=\\small]")
        
        if isinstance(raw_output, (dict, list)):
            parts.append(json.dumps(raw_output, indent=2))
        else:
            parts.append(str(raw_output))
            
        parts.append("\\end{Verbatim}")
        
    return "\n".join(parts)