# app/modules/report/tools_renderer.py
import json
from typing import Any, Dict
from .config import SEVERITY_WEIGHTS, TOOL_OBJECTIVES, TOOL_RECOMMENDATIONS
from .utils import _clean_text, _sanitize_data, _extract_text, _escape_latex

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
    normalized.setdefault("objective", TOOL_OBJECTIVES.get(tool, "Collect evidence."))
    normalized.setdefault("recommendations", [TOOL_RECOMMENDATIONS.get(tool, "Review findings.")])

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

    # Logique de génération de summary automatique
    if not normalized["summary"] and isinstance(data, dict):
        if data.get("open_ports_count") is not None:
            normalized["summary"] = f"{tool} reported {data.get('open_ports_count')} open port(s)."
        else:
            normalized["summary"] = f"{tool} completed with evidence."
            
    return _sanitize_data(normalized)

def render_nmap_data(data: Dict[str, Any]) -> str:
    parts = [f"\\textbf{{Host Status}}: {_escape_latex(str(data.get('status', 'unknown')))}\\\\"]
    open_ports = data.get("open_ports", [])
    if open_ports:
        parts.append("\\begin{itemize}")
        for port in open_ports:
            parts.append(f"  \\item Port {port.get('port')}/{port.get('protocol')}")
        parts.append("\\end{itemize}")
    return "\n".join(parts)

def render_verbatim(data: Any) -> str:
    try:
        dump = json.dumps(_sanitize_data(data), ensure_ascii=False, indent=2)
    except Exception:
        dump = repr(_sanitize_data(data))
    return "\\begin{Verbatim}[fontsize=\\small]\n" + dump + "\n\\end{Verbatim}"