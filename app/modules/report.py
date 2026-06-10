import os
import re
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
    title = f"\\section*{{{_escape_latex(tool.title())}}}"
    if isinstance(data, dict) and data.get("error"):
        return title + "\n\\textbf{Error}: " + _escape_latex(str(data.get("error")))

    if tool == "nmap" and isinstance(data, dict):
        return title + "\n" + _render_nmap_data(data)

    if tool in {"ffuf", "searchsploit"} and isinstance(data, dict):
        summary_name = "vulnerabilities" if tool == "ffuf" else "exploits"
        summary_count = data.get(f"{summary_name}_count", len(data.get(summary_name, [])))
        parts = ["\\textbf{Summary}: " + _escape_latex(str(summary_count))]
        if data.get(summary_name):
            parts.append("\\subsection*{Details}")
            parts.append(_render_itemize(data[summary_name]))
        return title + "\n" + "\n".join(parts)

    if tool == "hydra" and isinstance(data, dict):
        parts = ["\\textbf{Cracked Passwords}: " + _escape_latex(str(data.get("cracked_passwords_count", 0)))]
        if data.get("cracked_passwords"):
            parts.append("\\subsection*{Passwords}")
            parts.append(_render_itemize(data["cracked_passwords"]))
        return title + "\n" + "\n".join(parts)

    if isinstance(data, dict):
        return title + "\n" + _render_itemize(data)

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
