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
	itle{%s}
\date{}
\maketitle
\section*{Summary}
Generated results from automated pentest pipeline.
\section*{Details}
%s
\end{document}
"""


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


def _render_results_as_latex(results: Dict[str, Any]) -> str:
    parts = []
    for tool, data in results.items():
        parts.append(f"\\subsection*{{{_escape_latex(tool)}}}")
        parts.append("\\begin{verbatim}")
        # pretty JSON for readability (verbatim will protect special chars)
        try:
            dump = json.dumps(data, ensure_ascii=False, indent=2)
        except Exception:
            dump = repr(data)
        parts.append(dump)
        parts.append("\\end{verbatim}")

    return "\n".join(parts)


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
    safe_title = _escape_latex(title)
    tex_body = _render_results_as_latex(results)
    tex = LATEX_TEMPLATE % (safe_title, tex_body)

    # ensure output directory exists
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        tex_path = os.path.join(td, "report.tex")
        with open(tex_path, "w", encoding="utf-8") as f:
            f.write(tex)

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
