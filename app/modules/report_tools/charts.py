# app/modules/report_tools/charts.py
from collections import Counter
from pathlib import Path
import matplotlib.pyplot as plt

# Color scheme aligned with LaTeX definitions
VULN_COLORS = {
    "critical": "#FF4D4D",  # Vivid Red
    "high": "#FF944D",      # Orange
    "medium": "#FFDB4D",    # Yellow
    "weak": "#FFDB4D",      # Yellow alias
    "low": "#4DFF4D"        # Vibrant Green
}

def generate_charts(results_list):
    severity_counter = Counter()
    for result in results_list:
        severity = result.get("severity", "low").lower()
        if severity not in severity_counter:
            severity_counter[severity] = 0
        severity_counter[severity] += 1

    chart_dir = Path("/tmp/pentest_charts")
    chart_dir.mkdir(exist_ok=True)
    severity_chart = chart_dir / "severity_chart.png"

    # Filter to display only categories present (> 0)
    labels = [k.upper() for k in severity_counter.keys() if severity_counter[k] > 0]
    sizes = [v for v in severity_counter.values() if v > 0]
    colors = [VULN_COLORS.get(k.lower(), "#4D94FF") for k in severity_counter.keys() if severity_counter[k] > 0]

    if not sizes:
        labels, sizes, colors = ["NO FINDINGS"], [1], ["#4D94FF"]

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140, textprops={'weight': 'bold'})
    plt.title("Vulnerabilities Breakdown by Severity Level")
    plt.savefig(severity_chart, bbox_inches="tight", dpi=150)
    plt.close()
    return {"severity_chart": str(severity_chart)}

def generate_tool_chart(results_list):
    tool_counter = Counter()
    for result in results_list:
        tool = result.get("tool", "unknown")
        # Initialize count or extract length of findings safely
        findings_count = len(result.get("findings", [])) if isinstance(result.get("findings"), list) else 1
        tool_counter[tool] += max(1, findings_count)

    chart_dir = Path("/tmp/pentest_charts")
    chart_dir.mkdir(exist_ok=True)
    output_file = chart_dir / "tool_chart.png"

    plt.figure(figsize=(8, 5))
    plt.bar(list(tool_counter.keys()), list(tool_counter.values()), color="#4D94FF")
    plt.title("Detected Findings / Artifacts Count per Module")
    plt.xlabel("Security Modules")
    plt.ylabel("Findings Count")
    plt.xticks(rotation=15)
    plt.savefig(output_file, bbox_inches="tight", dpi=150)
    plt.close()
    return {"tool_chart": str(output_file)}