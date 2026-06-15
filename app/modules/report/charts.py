# app/modules/report/charts.py
from collections import Counter
from pathlib import Path
import matplotlib.pyplot as plt

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

    plt.figure(figsize=(6, 6))
    plt.pie(list(severity_counter.values()), labels=list(severity_counter.keys()), autopct="%1.1f%%")
    plt.title("Répartition des vulnérabilités")
    plt.savefig(severity_chart, bbox_inches="tight")
    plt.close()
    return {"severity_chart": str(severity_chart)}

def generate_tool_chart(results_list):
    tool_counter = Counter()
    for result in results_list:
        tool = result.get("tool", "unknown")
        tool_counter[tool] += 1

    chart_dir = Path("/tmp/pentest_charts")
    chart_dir.mkdir(exist_ok=True)
    output_file = chart_dir / "tool_chart.png"

    plt.figure(figsize=(8, 5))
    plt.bar(tool_counter.keys(), tool_counter.values())
    plt.title("Résultats par module")
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    return str(output_file)