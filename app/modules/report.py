# app/modules/report.py
import os
import re
import subprocess
import tempfile
from typing import Dict, Any

from app.modules.report_tools.config import SEVERITY_WEIGHTS
from app.modules.report_tools.utils import _escape_latex
from app.modules.report_tools.charts import generate_charts, generate_tool_chart
from app.modules.report_tools.templates import LATEX_TEMPLATE, render_methodology_page, render_architecture_page
from app.modules.report_tools.tools_renderer import (
    normalize_tool_result,
    _render_top_vulnerabilities,
    _criticality_matrix_rows,
    _render_criticality_matrix,
    _render_tool_page,
    _render_annex_page
)

TEMPLATE_PLACEHOLDER = "%%REPORT_CONTENT%%"
TITLE_PLACEHOLDER = "%%REPORT_TITLE%%"

def _risk_level_label(score: int) -> str:
    if score >= 75: return "[CRITICAL] High Infrastructure Exposure"
    if score >= 50: return "[MEDIUM] Moderate System Exposure"
    if score >= 25: return "[LOW] Controlled System Exposure"
    return "[INFO] Secured / Low Risk Profile"

def build_global_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    normalized = {tool: normalize_tool_result(tool, data) for tool, data in results.items()}
    severity_breakdown = {label: 0 for label in ("low", "medium", "high", "critical")}
    total_findings = 0
    risk_score = 0
    tool_scores = {}

    for tool, data in normalized.items():
        severity = data.get("severity", "medium")
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

        findings = data.get("findings") or []
        total_findings += len(findings)
        risk_score += SEVERITY_WEIGHTS.get(severity, 2) * max(1, len(findings))
        tool_scores[tool] = min(20, SEVERITY_WEIGHTS.get(severity, 2) * 5)

    recommendations = []
    for tool, data in normalized.items():
        recs = data.get("recommendations") or []
        if isinstance(recs, str):
            recs = [recs]
        elif isinstance(recs, dict):
            recs = [str(recs)]
        recommendations.extend(recs)

    score = min(100, risk_score)
    return {
        "total_tools": len(normalized),
        "total_findings": total_findings,
        "severity_breakdown": severity_breakdown,
        "risk_score": score,
        "risk_level": _risk_level_label(score),
        "recommendations": list(dict.fromkeys(recommendations))[:8],
        "tool_scores": tool_scores,
    }

def _load_report_template() -> str:
    template_path = os.path.join(os.path.dirname(__file__), "model", "report.tex")
    try:
        with open(template_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            if content and isinstance(content, str):
                return content
            return str(LATEX_TEMPLATE)
    except Exception:
        return str(LATEX_TEMPLATE)

def _render_chart_section(chart_paths: dict[str, str]) -> str:
    if not chart_paths:
        return ""
    parts = ["\\section*{Data Visualizations and Metrics Mapping}", "\\begin{figure}[H]", "\\centering"]
    if chart_paths.get("severity_chart"):
        parts.append(f"\\includegraphics[width=0.7\\linewidth]{{{_escape_latex(chart_paths['severity_chart'])}}}")
        parts.append("\\caption{Global Vulnerability Breakdown by Severity}")
    if chart_paths.get("tool_chart"):
        parts.append("\\vspace{5mm}")
        parts.append(f"\\includegraphics[width=0.8\\linewidth]{{{_escape_latex(chart_paths['tool_chart'])}}}")
        parts.append("\\caption{Identified Findings Count per Tool Module}")
    parts.append("\\end{figure}")
    return "\n".join(parts)

def _render_summary_page(results: Dict[str, Any]) -> str:
    normalized = {tool: normalize_tool_result(tool, data) for tool, data in results.items()}
    summary = build_global_summary(normalized)
    tests = sorted(normalized.keys())

    parts = [
        "\\section*{Executive Summary}",
        "\\subsection*{Overall Calculated Risk Profile}",
        f"\\textbf{{{_escape_latex(summary['risk_level'])}}}\\\\",
        "\\subsection*{High-Level Assessment Metrics}",
        "\\begin{itemize}",
        f"  \\item Total orchestrated modules executed: {summary['total_tools']}",
        f"  \\item Total consolidated security findings: {summary['total_findings']}",
        f"  \\item Evaluated system risk score: {summary['risk_score']} / 100",
        "\\end{itemize}",
        _render_top_vulnerabilities(normalized),
        "\n\\subsection*{Remediation and Patching Timeframe Windows}\n\\begin{itemize}\n  \\item Critical Findings: Remediation required within 48 Hours.\n  \\item High Findings: Remediation required within 7 Days.\n  \\item Medium / Low Findings: Remediation scheduled within 30-90 Days.\n\\end{itemize}",
        _render_criticality_matrix(_criticality_matrix_rows(normalized)),
        "\\subsection*{Metrics Distribution Overview}",
        "\\begin{itemize}",
    ]
    for label, count in summary["severity_breakdown"].items():
        if count:
            parts.append(f"  \\item {label.title()} Findings Count: {count}")
    parts.append("\\end{itemize}")
    parts.append("\\subsection*{Consolidated Hardening Action Plan}")
    parts.append("\\begin{itemize}")
    for recommendation in summary["recommendations"]:
        parts.append(f"  \\item {_escape_latex(str(recommendation))}")
    parts.append("\\end{itemize}")
    
    # Lignes corrigées ici : Séparation stricte en deux instructions .append() distinctes
    parts.append("\\subsection*{Operational Module Registry}")
    parts.append("\\begin{itemize}")
    
    for tool in tests:
        data = normalized[tool]
        severity = data.get("severity", "medium")
        parts.append(
            f"  \\item \\textbf{{{_escape_latex(tool.upper())}}}: Run Status -> Completed. Base calculated risk profile: \\textbf{{{severity.upper()}}}"
        )
    parts.append("\\end{itemize}")
    return "\n".join(parts)

def _render_results_as_latex(results: Dict[str, Any]) -> str:
    normalized = {tool: normalize_tool_result(tool, data) for tool, data in results.items()}
    charts = {}
    try:
        # 1. On récupère le dictionnaire du premier graphique (severity_chart)
        severity_chart_res = generate_charts(list(normalized.values()))
        
        # 2. On récupère le dictionnaire du second graphique (tool_chart)
        tool_chart_res = generate_tool_chart(list(normalized.values()))
        
        # 3. On extrait proprement la chaîne de caractères (le chemin absolu vers le fichier)
        charts = {
            "severity_chart": severity_chart_res.get("severity_chart"),
            "tool_chart": tool_chart_res.get("tool_chart") if isinstance(tool_chart_res, dict) else tool_chart_res
        }
    except Exception:
        charts = {}

    pages = [
        _render_summary_page(normalized),
        _render_chart_section(charts),
        render_methodology_page(),
        render_architecture_page(),
    ]
    for tool, data in normalized.items():
        pages.append(_render_tool_page(tool, data))
    pages.append(_render_annex_page(normalized))
    return "\n\\newpage\n".join(pages)

def _find_host_mount_candidates():
    candidates = [os.environ.get("HOST_OUTPUT_DIR"), "/host", "/host_mnt", "/mnt", "/app", "/workspace"]
    return [c for c in candidates if c]

def _is_mount(path: str) -> bool:
    try:
        return os.path.ismount(path)
    except Exception:
        return False

def generate_pdf_report(results: Dict[str, Any], title: Any, output_path: str, copy_to_host: bool = False, host_dest: str | None = None) -> Dict[str, Any]:
    if isinstance(title, dict):
        clean_title = str(title.get("title", title.get("text", "Pentest Automation Report")))
    else:
        clean_title = str(title) if title else "Pentest Automation Report"

    loaded_template = _load_report_template()
    if not isinstance(loaded_template, str):
        template = str(LATEX_TEMPLATE)
    else:
        template = loaded_template
    
    if "\\usepackage{float}" not in template:
        template = template.replace("\\begin{document}", "\\usepackage{float}\n\\begin{document}")

    tex_body = _render_results_as_latex(results)
    
    if TEMPLATE_PLACEHOLDER in template:
        template = template.replace(TEMPLATE_PLACEHOLDER, tex_body)
    elif "\\end{document}" in template:
        template = template.replace("\\end{document}", tex_body + "\n\\end{document}")
    else:
        template = (str(LATEX_TEMPLATE) % tex_body) if "%s" in str(LATEX_TEMPLATE) else f"{LATEX_TEMPLATE}\n{tex_body}"

    if TITLE_PLACEHOLDER in template:
        template = template.replace(TITLE_PLACEHOLDER, _escape_latex(clean_title))
    else:
        try:
            if re.search(r"\\title\s*\{.*?\}", template, flags=re.S):
                template = re.sub(r"\\title\s*\{.*?\}", f"\\title{{{_escape_latex(clean_title)}}}", template, flags=re.S)
            else:
                template = template.replace(
                    "\\begin{document}",
                    f"\\title{{{_escape_latex(clean_title)}}}\n\\begin{{document}}",
                )
            if "\\maketitle" in template and "\\title" in template and template.find("\\maketitle") < template.find("\\title"):
                template = template.replace("\\maketitle", "")
                template = template.replace("\\begin{document}", "\\begin{document}\n\\maketitle", 1)
        except Exception:
            pass

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        tex_path = os.path.join(td, "report.tex")
        with open(tex_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(template)
        
        logo_src = os.path.join(os.path.dirname(__file__), "model", "swissknife_logo.jpg")
        if os.path.exists(logo_src):
            import shutil
            shutil.copy2(logo_src, os.path.join(td, "swissknife_logo.jpg"))

        try:
            generated_pdf = os.path.join(td, "report.pdf")
            last_stdout, last_stderr = "", ""
            
            # Exécution des passes de compilation
            for i in range(2):
                proc = subprocess.run(
                    ["pdflatex", "-interaction=nonstopmode", "report.tex"],
                    cwd=td,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )
                last_stdout = proc.stdout
                last_stderr = proc.stderr

            # --- CORRECTIF : Tolérance aux codes de retour si le PDF est bien généré ---
            if not os.path.exists(generated_pdf) or os.path.getsize(generated_pdf) == 0:
                return {
                    "error": "pdflatex compilation failure",
                    "log": last_stdout + last_stderr,
                }
            
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
                        if os.path.abspath(dest) != os.path.abspath(output_path):
                            shutil.copy2(output_path, dest)
                        info["copied_to_host"] = dest
                    except Exception as e:
                        info["copied_to_host"] = None
                        info["copy_error"] = str(e)
                else:
                    copied = False
                    for cand in _find_host_mount_candidates():
                        if not cand:
                            continue
                        if _is_mount(cand) or os.path.exists(cand):
                            try:
                                dest = os.path.join(cand, os.path.basename(output_path))
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
            return {"error": "pdflatex binary not found within environment path"}
        except Exception as e:
            return {"error": str(e)}