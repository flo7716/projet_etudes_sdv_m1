# app/modules/report/tools_renderer.py
import json
from typing import Any, Dict, List
from .config import SEVERITY_WEIGHTS, TOOL_OBJECTIVES, TOOL_RECOMMENDATIONS
from .utils import _clean_text, _sanitize_data, _extract_text, _escape_latex, _truncate_text

def normalize_tool_result(tool: str, data: Any, target: str | None = None) -> Dict[str, Any]:
    if isinstance(data, dict) and data.get("tool") and "findings" in data:
        normalized = dict(data)
    else:
        normalized = dict(data) if isinstance(data, dict) else {"raw_output": data}

    normalized.setdefault("tool", tool)
    normalized.setdefault("target", target or (data.get("target") if isinstance(data, dict) else None))
    normalized.setdefault("summary", "")
    normalized.setdefault("findings", [])
    normalized.setdefault("raw_output", data)
    normalized.setdefault("objective", TOOL_OBJECTIVES.get(tool, "Collect evidence and highlight exposure areas."))
    normalized.setdefault("recommendations", [TOOL_RECOMMENDATIONS.get(tool, "Review and remediate the reported findings promptly.")])

    # Logique d'adaptation de sévérité par outil
    severity = "low"
    if isinstance(data, dict) and data.get("severity"):
        severity = data.get("severity").lower()
    elif isinstance(data, dict):
        if tool == "nmap":
            severity = "medium" if data.get("open_ports_count", 0) > 10 else "low"
        elif tool in ["gobuster", "ffuf"]:
            severity = "medium" if data.get("found_paths_count", 0) > 5 else "low"
        elif tool in ["nikto", "nuclei"]:
            vulns = data.get("vulnerabilities_count", 0) or data.get("findings_count", 0)
            raw_str = str(data.get("raw_output", "")).lower()
            if vulns > 3 or "critical" in raw_str or "rce" in raw_str: severity = "critical"
            elif vulns > 0 or "high" in raw_str: severity = "high"
        elif tool in ["sqlmap", "hydra", "john"]:
            has_findings = len(data.get("findings", [])) > 0 or data.get("cracked_passwords_count", 0) > 0
            severity = "critical" if tool == "sqlmap" and has_findings else ("high" if has_findings else "low")

    if severity not in SEVERITY_WEIGHTS: severity = "medium"
    normalized["severity"] = severity

    # Extraction des preuves (findings) manquantes
    findings = normalized.get("findings") or []
    if not findings and isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "cracked_passwords", "open_ports", "found_paths"):
            value = data.get(key)
            if isinstance(value, list) and value:
                findings = [_extract_text(item) for item in value if _extract_text(item)]
                break
    if not findings and isinstance(data, str):
        findings = [line.strip() for line in data.splitlines() if line.strip()][:8]
    normalized["findings"] = findings

    # Logique de génération de summary automatique
    if not normalized["summary"] and isinstance(data, dict):
        if data.get("open_ports_count") is not None:
            normalized["summary"] = f"{tool} reported {data.get('open_ports_count')} open port(s)."
        else:
            normalized["summary"] = f"{tool} completed with evidence."
            
    return _sanitize_data(normalized)


# ==========================================
# FONCTIONS MANQUANTES DE L'EXECUTIVE SUMMARY
# ==========================================

def _extract_top_vulnerabilities(normalized_results: Dict[str, Any], limit: int = 5) -> List[Dict[str, str]]:
    """Extrait et trie les vulnérabilités les plus critiques trouvées par les outils."""
    entries = []
    for tool, data in normalized_results.items():
        severity = data.get("severity", "medium")
        findings = data.get("findings") or []
        if findings:
            entries.append({"tool": tool, "finding": _truncate_text(str(findings[0])), "severity": severity})
        elif data.get("summary"):
            entries.append({"tool": tool, "finding": _truncate_text(str(data.get("summary"))), "severity": severity})
    entries.sort(key=lambda item: SEVERITY_WEIGHTS.get(item["severity"], 2), reverse=True)
    return entries[:limit]


def _render_top_vulnerabilities(normalized_results: Dict[str, Any], limit: int = 5) -> str:
    """Génère le rendu LaTeX de la liste des principales vulnérabilités."""
    entries = _extract_top_vulnerabilities(normalized_results, limit)
    if not entries:
        return "Aucune vulnérabilité structurée n'a été extraite."
    lines = ["\\subsection*{Principales vulnérabilités}", "\\begin{enumerate}"]
    for entry in entries:
        lines.append(f"  \\item \\textbf{{{_escape_latex(entry['tool'].title())}}} ({entry['severity'].title()}): {_escape_latex(entry['finding'])}")
    lines.append("\\end{enumerate}")
    return "\n".join(lines)


def _criticality_matrix_rows(normalized_results: Dict[str, Any], limit: int = 4) -> List[Dict[str, str]]:
    """Formate les lignes pour alimenter la matrice de criticité."""
    rows = []
    top_vulns = _extract_top_vulnerabilities(normalized_results, limit)
    mapping = {
        "critical": ("Élevé", "Élevée", "Critique"),
        "high": ("Élevé", "Moyenne", "Haute"),
        "medium": ("Moyen", "Moyenne", "Moyenne"),
        "low": ("Faible", "Élevée", "Faible"),
    }
    for entry in top_vulns:
        impact, probability, criticality = mapping.get(entry["severity"], ("Moyen", "Moyenne", "Moyenne"))
        rows.append({
            "vulnerability": entry["finding"],
            "impact": impact,
            "probability": probability,
            "criticality": criticality,
        })
    return rows


def _render_criticality_matrix(rows: List[Dict[str, str]]) -> str:
    """Génère le tableau LaTeX représentant la matrice de criticité."""
    if not rows:
        return ""
    lines = [
        "\\subsection*{Matrice de criticité}",
        "\\begin{tabular}{|p{6cm}|c|c|c|}",
        "\\hline",
        "\\textbf{Vulnérabilité} & \\textbf{Impact} & \\textbf{Probabilité} & \\textbf{Criticité}\\\\",
        "\\hline",
    ]
    for row in rows:
        lines.append(
            f"{_escape_latex(row['vulnerability'])} & {_escape_latex(row['impact'])} & {_escape_latex(row['probability'])} & {_escape_latex(row['criticality'])}\\\\"
        )
        lines.append("\\hline")
    lines.append("\\end{tabular}")
    return "\n".join(lines)


# ==========================================
# FONCTIONS DE RENDU DES PAGES INDIVIDUELLES
# ==========================================

def render_nmap_data(data: Dict[str, Any]) -> str:
    parts = [f"\\textbf{{Host Status}}: {_escape_latex(str(data.get('status', 'unknown')))}\\\\"]
    open_ports = data.get("open_ports", [])
    if open_ports:
        parts.append("\\begin{itemize}")
        for port in open_ports:
            if isinstance(port, dict):
                parts.append(f"  \\item Port {port.get('port')}/{port.get('protocol')} - {port.get('state', 'open')}")
            else:
                parts.append(f"  \\item Port {_escape_latex(str(port))}")
        parts.append("\\end{itemize}")
    return "\n".join(parts)


def render_verbatim(data: Any) -> str:
    try:
        dump = json.dumps(_sanitize_data(data), ensure_ascii=False, indent=2)
    except Exception:
        dump = repr(_sanitize_data(data))
    return "\\begin{Verbatim}[fontsize=\\small]\n" + dump + "\n\\end{Verbatim}"


def _render_tool_page(tool: str, data: Any) -> str:
    """Génère la page de rapport détaillée d'un outil donné."""
    normalized = normalize_tool_result(tool, data)
    title = f"\\section*{{{_escape_latex(tool.title())}}}"

    if normalized.get("error"):
        return title + "\n\\textbf{Error}: " + _escape_latex(str(normalized.get("error")))

    findings = normalized.get("findings") or []
    recommendations = normalized.get("recommendations") or []
    severity = normalized.get("severity", "medium")

    sections = [
        "\\subsection*{Objectif}",
        _escape_latex(normalized.get("objective")) + "\\\\",
        "\\subsection*{Cible}",
        _escape_latex(str(normalized.get("target") or "Non spécifié")) + "\\\\",
        "\\subsection*{Résumé}",
        _escape_latex(str(normalized.get("summary"))) + "\\\\",
        "\\subsection*{Preuves}",
    ]

    if findings:
        sections.append("\\begin{itemize}")
        for item in findings[:4]:
            sections.append(f"  \\item {_escape_latex(str(item))}")
        sections.append("\\end{itemize}")
    else:
        sections.append("Aucune preuve structurée disponible. Voir l'annexe technique.\\\\")

    sections.extend(["\\subsection*{Impact}", "\\begin{itemize}"])
    if severity == "critical":
        sections.append("  \\item Impact critique : Accès non autorisé complet ou exécution de code à distance (RCE).")
    elif severity == "high":
        sections.append("  \\item Impact élevé : Risque important de fuite de données ou compromission d'application.")
    elif severity == "medium":
        sections.append("  \\item Impact moyen : Exposition d'informations sensibles nécessitant un correctif rapide.")
    else:
        sections.append("  \\item Impact faible : Risque minimal direct, conseil de durcissement.")
    sections.append("\\end{itemize}")

    sections.extend(["\\subsection*{Remédiation}", "\\begin{itemize}"])
    for recommendation in recommendations[:5]:
        sections.append(f"  \\item {_escape_latex(str(recommendation))}")
    sections.append("\\end{itemize}")
    
    sections.extend([
        "\\subsection*{Niveau de risque}",
        f"{_escape_latex(severity.title())}\\\\"
    ])

    if tool == "nmap":
        sections.append("\\subsection*{Détails réseau}")
        sections.append(render_nmap_data(normalized))

    return title + "\n" + "\n".join(sections)


def _render_annex_page(normalized_results: Dict[str, Any]) -> str:
    """Génère l'annexe de fin de document avec les données brutes."""
    parts = ["\\section*{Annexe: détails techniques bruts}"]
    for tool, data in normalized_results.items():
        raw_output = data.get("raw_output")
        if not raw_output:
            continue
        parts.append(f"\\subsection*{{{_escape_latex(tool.title())}}}")
        parts.append(render_verbatim(raw_output))
    return "\n".join(parts)