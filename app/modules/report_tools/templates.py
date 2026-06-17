# app/modules/report_tools/templates.py
LATEX_TEMPLATE = r"""\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\usepackage{float}
\usepackage{graphicx}
\usepackage{amsmath}
\usepackage{fancyvrb}
\usepackage[table]{xcolor}

% --- AJOUT DE LISTINGS POUR LES OUTPUTS BRUTS ---
\usepackage{listings}
\lstset{
    basicstyle=\small\ttfamily,
    breaklines=true,            % Active la coupure automatique
    breakatwhitespace=false,    % Coupe même au milieu des mots si nécessaire
    frame=single,               % Ajoute un cadre fin esthétique autour du bloc
    backgroundcolor=\color{gray!5}, % Un léger fond gris clair pour le code
    columns=fullflexible,
    keepspaces=true
}

\definecolor{gray!20}{HTML}{E0E0E0}
\definecolor{vulncritical}{HTML}{FF4D4D}
\definecolor{vulnhigh}{HTML}{FF944D}
\definecolor{vulnmedium}{HTML}{FFDB4D}
\definecolor{vulnlow}{HTML}{4DFF4D}

\geometry{margin=1in}
\begin{document}
%s
\end{document}
"""

def render_methodology_page() -> str:
    return "\n".join([
        "\\section*{Automated Pipeline Methodology}",
        "The Swissknife security assessment framework orchestrates operations sequentially:",
        "\\begin{itemize}",
        "  \\item Target Infrastructure Mapping (Nmap)",
        "  \\item TLS/SSL Protocol Hardening Verification (Sslyze)",
        "  \\item External Threat Vector and Content Enumeration (Gobuster, Ffuf)",
        "  \\item Application Vulnerability Assessment (Nikto, Nuclei)",
        "  \\item Automated Database Exploitation Flow (Sqlmap)",
        "  \\item Aggregation and Structural Report Generation (LaTeX Engine)",
        "\\end{itemize}",
    ])

def render_architecture_page() -> str:
    return "\n".join([
        "\\section*{Toolbox System Architecture Overivew}",
        "The system relies on an isolated, non-exposed interactive CLI wrapper interface to guarantee local security.",
        "\\begin{center}",
        "\\begin{tabular}{c}",
        "Security Operator / Analyst \\\\",
        "$\\downarrow$ \\\\",
        "Python 3.13 Sealed Interactive CLI \\\\",
        "$\\downarrow$ \\\\",
        "Docker Container Isolation Boundary \\\\",
        "$\\downarrow$ \\\\",
        "Subprocess Binary Execution (Nmap, SQLMap, Nuclei...) \\\\",
        "$\\downarrow$ \\\\",
        "Dynamic JSON/XML Logging Data Parsing Engine \\\\",
        "$\\downarrow$ \\\\",
        "Structured LaTeX Compilation Engine (pdflatex) \\\\",
        "\\end{tabular}",
        "\\end{center}",
    ])