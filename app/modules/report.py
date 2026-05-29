import os
import subprocess
import tempfile
import json
from typing import Dict, Any


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


def _load_report_template() -> str:
    template_path = os.path.join(os.path.dirname(__file__), "model", "report.tex")
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return LATEX_TEMPLATE


def _render_summary_page(results: Dict[str, Any]) -> str:
    tests = sorted(results.keys())
    parts = ["\\section*{Summary}", "\\begin{itemize}"]
    for tool in tests:
        data = results[tool]
        status = "Completed"
        if isinstance(data, dict):
            if data.get("error"):
                status = f"Error: {data['error']}"
            elif data.get("note"):
                status = data["note"]
            elif tool == "nmap" and isinstance(data.get("open_ports_count"), int):
                status = f"{data['open_ports_count']} open ports"

        parts.append(
            f"  \\item \\textbf{{{_escape_latex(tool)}}}: {_escape_latex(str(status))}"
        )
    parts.append("\\end{itemize}")
    return "\n".join(parts)


def _render_verbatim(data: Any) -> str:
    try:
        dump = json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        dump = repr(data)
    return "\\begin{verbatim}\n" + dump + "\n\\end{verbatim}"


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
    title = f"\\section*{{{_escape_latex(tool.title())}}}"
    if isinstance(data, dict) and data.get("error"):
        return title + "\n\\textbf{Error}: " + _escape_latex(str(data.get("error")))
    if tool == "nmap" and isinstance(data, dict):
        return title + "\n" + _render_nmap_data(data)
    return title + "\n" + _render_verbatim(data)


def _render_results_as_latex(results: Dict[str, Any]) -> str:
    pages = [
        _render_summary_page(results),
    ]
    for tool, data in results.items():
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
    tex_body = _render_results_as_latex(results)
    if TEMPLATE_PLACEHOLDER in template:
        tex = template.replace(TEMPLATE_PLACEHOLDER, tex_body)
    elif "\\end{document}" in template:
        tex = template.replace("\\end{document}", tex_body + "\n\\end{document}")
    else:
        tex = LATEX_TEMPLATE % tex_body

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
                # if pdflatex failed but still produced a PDF, continue
                if proc.returncode != 0 and not os.path.exists(generated_pdf):
                    return {"error": "pdflatex failed", "log": proc.stdout + proc.stderr}
            # move to output path
            try:
                os.replace(generated_pdf, output_path)
            except OSError as e:
                # fallback when tmpdir and output are on different filesystems
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
            return {"error": "pdflatex not found. Install TeX Live (pdflatex)."}
        except Exception as e:
            return {"error": str(e)}
