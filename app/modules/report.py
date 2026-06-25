# app/modules/report.py
import os
import re
import subprocess
import tempfile
import shutil
import errno
from datetime import datetime
from typing import Dict, Any
import glob

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
    return str(LATEX_TEMPLATE)

def _render_chart_section(chart_paths: dict[str, str]) -> str:
    if not chart_paths:
        return ""
    parts = ["\\section*{Data Visualizations and Metrics Mapping}", "\\begin{figure}[H]", "\\centering"]
    if chart_paths.get("severity_chart"):
        parts.append(f"\\includegraphics[width=0.65\\linewidth]{{{_escape_latex(chart_paths['severity_chart'])}}}")
        parts.append("\\caption{Global Vulnerability Breakdown by Severity}")
    if chart_paths.get("tool_chart"):
        parts.append("\\vspace{3mm}")
        parts.append(f"\\includegraphics[width=0.75\\linewidth]{{{_escape_latex(chart_paths['tool_chart'])}}}")
        parts.append("\\caption{Identified Findings Count per Tool Module}")
    parts.append("\\end{figure}")
    return "\n".join(parts)

def _render_main_findings_page(results: Dict[str, Any]) -> str:
    """Generates a clean Executive Summary page without messy raw outputs."""
    normalized = {tool: normalize_tool_result(tool, data) for tool, data in results.items()}
    summary = build_global_summary(normalized)
    tests = sorted(normalized.keys())

    parts = [
        "\\section*{Executive Summary \\& Analytical Overview}",
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
        "\\subsection*{Metrics Distribution Overview}",
        "\\begin{itemize}",
    ]
    for label, count in summary["severity_breakdown"].items():
        if count:
            parts.append(f"  \\item {label.title()} Findings Count: {count}")
    parts.append("\\end{itemize}")
    
    if summary["recommendations"]:
        parts.append("\\subsection*{Consolidated Hardening Action Plan}")
        parts.append("\\begin{itemize}")
        for recommendation in summary["recommendations"]:
            parts.append(f"  \\item {_escape_latex(str(recommendation))}")
        parts.append("\\end{itemize}")
        
    parts.append("\\subsection*{Operational Module Registry}")
    parts.append("\\begin{itemize}")
    for tool in tests:
        data = normalized[tool]
        severity = data.get("severity", "medium")
        parts.append(f"  \\item \\textbf{{{_escape_latex(tool.upper())}}}: Run Status -> Completed. Base risk profile: \\textbf{{{severity.upper()}}}")
    parts.append("\\end{itemize}")
    
    return "\n".join(parts)

def _render_matrix_page(results: Dict[str, Any]) -> str:
    """Renders the matrix on its own dedicated section block."""
    normalized = {tool: normalize_tool_result(tool, data) for tool, data in results.items()}
    parts = [
        "\\section*{Consolidated Criticality Matrix Mapping}",
        "This registry compiles each active structural finding to its respective evaluated layer threat level.",
        _render_criticality_matrix(_criticality_matrix_rows(normalized))
    ]
    return "\n".join(parts)

def _render_results_as_latex(results: Dict[str, Any]) -> str:
    normalized = {tool: normalize_tool_result(tool, data) for tool, data in results.items()}
    charts = {}
    try:
        severity_chart_res = generate_charts(list(normalized.values()))
        tool_chart_res = generate_tool_chart(list(normalized.values()))
        
        charts = {
            "severity_chart": severity_chart_res.get("severity_chart"),
            "tool_chart": tool_chart_res.get("tool_chart") if isinstance(tool_chart_res, dict) else tool_chart_res
        }
    except Exception:
        charts = {}

    # --- STRICT PROFESSIONAL ACADEMIC SEQUENCING ---
    pages = [
        render_architecture_page(),
        render_methodology_page(),
        _render_main_findings_page(normalized),
        _render_matrix_page(normalized),
        _render_chart_section(charts),
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
    # 1. Proper extraction of the target host from the results dictionary
    target_host = "unknown_host"
    for tool, data in results.items():
        if isinstance(data, dict) and data.get("target"):
            raw_target = str(data["target"])
            clean_target = re.sub(r'https?://', '', raw_target).split(':')[0].strip('/')
            if clean_target:
                target_host = clean_target
                break

    # 2. unique timestamp for the report generation to avoid overwriting previous reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 3. Dynamic output path construction based on target host and timestamp
    base_filename = os.path.basename(output_path) or "security_report.pdf"
    new_results_dir = f"results_{target_host}_{timestamp}"
    output_path = os.path.join(new_results_dir, base_filename)

    # 4. Create a dedicated subdirectory for raw tool outputs
    raw_outputs_dir = os.path.join(new_results_dir, "tool_outputs")

    if isinstance(title, dict):
        clean_title = str(title.get("title", title.get("text", "Pentest Automation Report")))
    else:
        clean_title = str(title) if title else "Pentest Automation Report"

    template = _load_report_template()
    if "\\usepackage{float}" not in template:
        template = template.replace("\\begin{document}", "\\usepackage{float}\n\\begin{document}")

    tex_body = _render_results_as_latex(results)
    if TEMPLATE_PLACEHOLDER in template:
        template = template.replace(TEMPLATE_PLACEHOLDER, tex_body)
    elif "\\end{document}" in template:
        template = template.replace("\\end{document}", tex_body + "\n\\end{document}")

    if TITLE_PLACEHOLDER in template:
        template = template.replace(TITLE_PLACEHOLDER, _escape_latex(clean_title))

    # CRUCIAL : Creation of the results directory and raw outputs subdirectory before PDF generation
    os.makedirs(raw_outputs_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        tex_path = os.path.join(td, "report.tex")
        with open(tex_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(template)
        
        try:
            generated_pdf = os.path.join(td, "report.pdf")
            for i in range(2):
                subprocess.run(["pdflatex", "-interaction=nonstopmode", "report.tex"], cwd=td, capture_output=True)
            
            if not os.path.exists(generated_pdf):
                return {"error": "pdflatex compilation failed, report.pdf not found in tmp dir"}

            # Moving the generated PDF to the desired output path, handling cross-device issues
            try:
                os.replace(generated_pdf, output_path)
            except OSError as e:
                if e.errno == errno.EXDEV:
                    shutil.copy2(generated_pdf, output_path)
                    os.remove(generated_pdf)
                else:
                    raise

            # --- EXPORTATION AND COPYING OF RAW TOOL OUTPUTS ---
            # A. Capture and copy any existing nuclei raw output files to the raw_outputs_dir
            for file_path in glob.glob("nuclei_*.txt") + glob.glob("/tmp/nuclei_*.txt"):
                if os.path.exists(file_path):
                    try:
                        shutil.copy2(file_path, os.path.join(raw_outputs_dir, os.path.basename(file_path)))
                    except Exception:
                        pass

            # B. Extract and save raw outputs from each tool's results dictionary to the raw_outputs_dir
            for tool_name, data in results.items():
                raw_content = data.get("raw_output") if isinstance(data, dict) else data
                if raw_content:
                    txt_filename = f"{tool_name.lower()}_raw_output.txt"
                    txt_dest_path = os.path.join(raw_outputs_dir, txt_filename)
                    try:
                        with open(txt_dest_path, "w", encoding="utf-8", errors="replace") as txt_f:
                            if isinstance(raw_content, (dict, list)):
                                txt_f.write(json.dumps(raw_content, indent=2))
                            else:
                                txt_f.write(str(raw_content))
                    except Exception:
                        pass

            info = {"pdf_path": output_path, "results_directory": new_results_dir, "raw_outputs_directory": raw_outputs_dir}

            # If copy_to_host is True, attempt to copy the entire results directory to a host-mounted path
            if copy_to_host:
                actual_host_dest = os.path.join(host_dest, new_results_dir) if host_dest else None
                if actual_host_dest:
                    try:
                        # Recursive copy of the results directory to the specified host destination, handling existing directories
                        if os.path.exists(actual_host_dest):
                            shutil.rmtree(actual_host_dest)
                        shutil.copytree(new_results_dir, actual_host_dest)
                        info["copied_to_host"] = os.path.join(actual_host_dest, base_filename)
                    except Exception as e:
                        info["copy_error"] = str(e)
                else:
                    # Fallback on host mount candidates if no specific host_dest is provided
                    for cand in _find_host_mount_candidates():
                        if not cand: continue
                        if _is_mount(cand) or os.path.exists(cand):
                            try:
                                host_target_dir = os.path.join(cand, new_results_dir)
                                if os.path.exists(host_target_dir):
                                    shutil.rmtree(host_target_dir)
                                shutil.copytree(new_results_dir, host_target_dir)
                                info["copied_to_host"] = os.path.join(host_target_dir, base_filename)
                                break
                            except Exception:
                                continue
            return info
        except Exception as e:
            return {"error": str(e)}