# app/modules/report_tools/templates.py

LATEX_TEMPLATE = r"""\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\usepackage{float}
\usepackage{graphicx}
\usepackage{amsmath}
\usepackage{fancyvrb}
\usepackage{listings} % Centralisé ici !

% On charge xcolor avec l'option table en premier
\usepackage[table]{xcolor}

% --- CONFIGURATION DE LISTINGS (SÉCURISATION DES LIGNES TRÈS LONGUES) ---
\lstset{
    basicstyle=\small\ttfamily,
    breaklines=true,         % Active le retour à la ligne automatique
    breakatwhitespace=false, % Force la coupure même s'il n'y a pas d'espace
    columns=fullflexible,
    keepspaces=true
}

% --- DÉFINITIONS DES COULEURS ---
\definecolor{vuln_critical}{HTML}{FF4D4D}
\definecolor{vuln_high}{HTML}{FF944D}
\definecolor{vuln_medium}{HTML}{FFDB4D}
\definecolor{vuln_low}{HTML}{4DFF4D}

\definecolor{vulncritical}{HTML}{FF4D4D}
\definecolor{vulnhigh}{HTML}{FF944D}
\definecolor{vulnmedium}{HTML}{FFDB4D}
\definecolor{vulnlow}{HTML}{4DFF4D}
\definecolor{gray!20}{HTML}{E6E6E6}

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