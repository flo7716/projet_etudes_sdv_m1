# app/modules/report.py
import os
import re
import subprocess
import tempfile
from typing import Dict, Any

# Imports propres depuis nos nouveaux fichiers "minicodes"
# Note : Ajusté selon ton package 'app.modules.report_tools' fourni dans ton code
from app.modules.report_tools.config import SEVERITY_WEIGHTS
from app.modules.report_tools.utils import _escape_latex, _truncate_text
from app.modules.report_tools.charts import generate_charts, generate_tool_chart
from app.modules.report_tools.templates import LATEX_TEMPLATE, render_methodology_page, render_architecture_page

# Ajout des imports explicites de toutes les fonctions de rendu requises pour l'orchestration globale
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
    if score >= 75: return "[CRITIQUE] Elevé"
    if score >= 50: return "[MOYEN] Moyen"
    if score >= 25: return "[FAIBLE] Faible"
    return "[BAS] Bas"


def build_global_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Calcule les métriques globales et agrège les recommandations du rapport."""
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
    """Tente de charger un modèle de document report.tex personnalisé si disponible."""
    template_path = os.path.join(os.path.dirname(__file__), "model", "report.tex")
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return LATEX_TEMPLATE


def _render_chart_section(chart_paths: dict[str, str]) -> str:
    """Génère la section Visualisation en figeant les graphiques avec l'option [H]."""
    if not chart_paths:
        return ""
    parts = ["\\section*{Visualisation des données}", "\\begin{figure}[H]", "\\centering"]
    if chart_paths.get("severity_chart"):
        parts.append(f"\\includegraphics[width=0.7\\linewidth]{{{_escape_latex(chart_paths['severity_chart'])}}}")
        parts.append("\\caption{Répartition des vulnérabilités par criticité}")
    if chart_paths.get("tool_chart"):
        parts.append("\\vspace{5mm}")
        parts.append(f"\\includegraphics[width=0.8\\linewidth]{{{_escape_latex(chart_paths['tool_chart'])}}}")
        parts.append("\\caption{Nombre de résultats par outil}")
    parts.append("\\end{figure}")
    return "\n".join(parts)


def _render_summary_page(results: Dict[str, Any]) -> str:
    """Génère le code LaTeX complet pour la page Executive Summary."""
    normalized = {tool: normalize_tool_result(tool, data) for tool, data in results.items()}
    summary = build_global_summary(normalized)
    tests = sorted(normalized.keys())

    parts = [
        "\\section*{Executive Summary}",
        "\\subsection*{Niveau de risque global}",
        f"{_escape_latex(summary['risk_level'])}\\\\",
        "\\subsection*{Résumé rapide}",
        "\\begin{itemize}",
        f"  \\item Total des outils exécutés: {summary['total_tools']}",
        f"  \\item Total des vulnérabilités: {summary['total_findings']}",
        f"  \\item Score global de risque: {summary['risk_score']} / 100",
        "\\end{itemize}",
        _render_top_vulnerabilities(normalized),  # Désormais correctement importé et résolu
        "\n\\subsection*{Priorités de remédiation}\n\\begin{itemize}\n  \\Critique : \\item À corriger sous 7 jours\n  \\Elevé : \\item À corriger sous 30 jours\n  \\Faible : \\item À corriger sous 90 jours\n\\end{itemize}",
        _render_criticality_matrix(_criticality_matrix_rows(normalized)),  # Désormais correctement importé et résolu
        "\\subsection*{Répartition des vulnérabilités}",
        "\\begin{itemize}",
    ]
    for label, count in summary["severity_breakdown"].items():
        if count:
            parts.append(f"  \\item {label.title()}: {count}")
    parts.append("\\end{itemize}")
    parts.append("\\paragraph{Synthèse des recommandations}")
    parts.append("\\begin{itemize}")
    for recommendation in summary["recommendations"]:
        parts.append(f"  \\item {_escape_latex(str(recommendation))}")
    parts.append("\\end{itemize}")
    parts.append("\\subsection*{Statut par outil}")
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


def _render_results_as_latex(results: Dict[str, Any]) -> str:
    """Orchestre la construction séquentielle de chaque section du rapport."""
    normalized = {tool: normalize_tool_result(tool, data) for tool, data in results.items()}
    charts = {}
    try:
        charts = {
            **generate_charts(list(normalized.values())),
            "tool_chart": generate_tool_chart(list(normalized.values())),
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
        pages.append(_render_tool_page(tool, data))  # Désormais correctement importé et résolu
    pages.append(_render_annex_page(normalized))      # Désormais correctement importé et résolu
    return "\n\\newpage\n".join(pages)


def _find_host_mount_candidates():
    """Identifie les points de montage hôtes pour copier le rapport généré."""
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
    """
    Fonction principale (Maître) du module de reporting.
    Compile l'ensemble des résultats collectés sous forme de document PDF.
    """
    template = _load_report_template()
    
    # Injection dynamique sécurisée du package float nécessaire aux graphiques [H]
    if "\\usepackage{float}" not in template:
        template = template.replace("\\begin{document}", "\\usepackage{float}\n\\begin{document}")

    # Transformation des résultats en code LaTeX structuré
    tex_body = _render_results_as_latex(results)
    if TEMPLATE_PLACEHOLDER in template:
        tex = template.replace(TEMPLATE_PLACEHOLDER, tex_body)
    elif "\\end{document}" in template:
        tex = template.replace("\\end{document}", tex_body + "\n\\end{document}")
    else:
        tex = LATEX_TEMPLATE % tex_body

    # Injection dynamique du titre du document
    if title and TITLE_PLACEHOLDER in tex:
        tex = tex.replace(TITLE_PLACEHOLDER, _escape_latex(title))
    else:
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

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Création du dossier de build isolé et appels à pdflatex
    with tempfile.TemporaryDirectory() as td:
        tex_path = os.path.join(td, "report.tex")
        with open(tex_path, "w", encoding="utf-8") as f:
            f.write(tex)
        
        logo_src = os.path.join(os.path.dirname(__file__), "model", "swissknife_logo.jpg")
        if os.path.exists(logo_src):
            import shutil
            shutil.copy2(logo_src, os.path.join(td, "swissknife_logo.jpg"))

        try:
            generated_pdf = os.path.join(td, "report.pdf")
            last_stdout, last_stderr = "", ""
            
            # Deux passes indispensables pour stabiliser la matrice de criticité et les tables des matières
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
            
            # Déplacement du PDF du cache temporaire vers la destination finale
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

            # Gestion de la copie persistante vers l'espace de stockage de la machine hôte
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
            return {"error": "pdflatex not found"}
        except Exception as e:
            return {"error": str(e)}