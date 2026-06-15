# app/modules/report/templates.py

LATEX_TEMPLATE = r"""
\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\usepackage{float}
\geometry{margin=1in}
\begin{document}
%s
\end{document}
"""

def render_methodology_page() -> str:
    return "\n".join([
        "\\section*{Méthodologie}",
        "\\begin{itemize}",
        "  \\item Reconnaissance (Nmap)",
        "  \\item Énumération web (Gobuster, Ffuf)",
        "  \\item Analyse de vulnérabilités (Nikto, Nuclei)",
        "  \\item Analyse TLS (Sslyze)",
        "  \\item Génération du rapport",
        "\\end{itemize}",
    ])

def render_architecture_page() -> str:
    return "\n".join([
        "\\section*{Architecture de la toolbox}",
        "\\begin{center}",
        "\\begin{tabular}{c}",
        "Utilisateur \\\\", "$\\downarrow$ \\\\",
        "CLI Interactive \\\\", "$\\downarrow$ \\\\",
        "Modules Python \\\\", "$\\downarrow$ \\\\",
        "Docker Kali \\\\", "$\\downarrow$ \\\\",
        "Outils de Pentest",
        "\\end{tabular}",
        "\\end{center}",
    ])