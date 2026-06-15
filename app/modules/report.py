# app/modules/report.py
import os
import re
import subprocess
import tempfile
from typing import Dict, Any

# Imports propres depuis nos nouveaux fichiers "minicodes"
from app.modules.report.config import SEVERITY_WEIGHTS
from app.modules.report.utils import _escape_latex, _truncate_text
from app.modules.report.charts import generate_charts, generate_tool_chart
from app.modules.report.templates import LATEX_TEMPLATE, render_methodology_page, render_architecture_page
from app.modules.report.tools_renderer import normalize_tool_result, render_nmap_data, render_verbatim

def _risk_level_label(score: int) -> str:
    if score >= 75: return "[CRITIQUE] Elevé"
    if score >= 50: return "[MOYEN] Moyen"
    if score >= 25: return "[FAIBLE] Faible"
    return "[BAS] Bas"

# ... Reste du code d'orchestration (generate_pdf_report, _render_results_as_latex) ...
# (Il va appeler intelligemment les modules importés ci-dessus)