# app/modules/report_tools/templates.py

LATEX_TEMPLATE = r"""\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\usepackage{float}
\usepackage{graphicx}
\usepackage{amsmath}
\usepackage{fancyvrb}
\usepackage{listings}
\usepackage{tcolorbox} % Added for stylized containers and alert cards

\usepackage[table]{xcolor}

\lstset{
    basicstyle=\small\ttfamily,
    breaklines=true,
    breakatwhitespace=false,
    columns=fullflexible,
    keepspaces=true
}

% --- HARMONIZED COLOR PALETTE ---
\definecolor{vulncritical}{HTML}{FF4D4D}
\definecolor{vulnhigh}{HTML}{FF944D}
\definecolor{vulnmedium}{HTML}{FFDB4D}
\definecolor{vulnlow}{HTML}{4DFF4D}
\definecolor{graybg}{HTML}{F8F9FA}

% --- MACRO FOR ALERT CARDS ---
\newcommand{\alertcard}[3]{
    \vspace{1mm}
    \begin{tcolorbox}[colback=graybg, colframe=#1, arc=1.5mm, boxrule=0.6mm, left=3mm, right=3mm, top=2mm, bottom=2mm]
        \textbf{\textcolor{#1}{[#2]}} #3
    \end{tcolorbox}
    \vspace{1mm}
}

\geometry{margin=1in}

\begin{document}

% --- PROFESSIONAL COVER PAGE ---
\begin{titlepage}
    \centering
    \vspace*{1.5cm}
    \includegraphics[width=0.35\linewidth]{../modules/model/swissknife_logo.jpg}\\[1cm]
    
    {\scshape\LARGE SDV School --- Master 1 Cybersecurity \par}
    \vspace{0.8cm}
    {\scshape\Large Final Study Project --- SwissKnife Orchestrator \par}
    \vspace{1.5cm}
    {\huge\bfseries %%REPORT_TITLE%% \par}
    \vspace{0.5cm}
    {\large\textsl{Automated Security Pipeline Assessment Deliverable} \par}
    
    \vfill
    \begin{minipage}{0.4\textwidth}
        \begin{flushleft} \large
            \break\emph{Author:}\\
            Security Operator
        \end{flushleft}
    \end{minipage}
    ~
    \begin{minipage}{0.4\textwidth}
        \begin{flushright} \large
            \break\emph{Evaluated By:} \\
            Examination Jury
        \end{flushright}
    \end{minipage}
    
    \vfill
    {\large \today \par}
\end{titlepage}

\newpage

%%REPORT_CONTENT%%

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
        "\\section*{Toolbox System Architecture Overview}",
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