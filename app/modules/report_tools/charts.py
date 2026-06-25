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
    
    # Forced initialization of all severity categories to ensure consistent chart representation, even if some categories have zero findings
    for cat in ["critical", "high", "medium", "low"]:
        severity_counter[cat] = 0

    for result in results_list:
        tool = str(result.get("tool", "")).upper()
        findings = result.get("findings", [])
        
        # If the tool is NUCLEI, we parse the findings to count the number of occurrences per severity level, as NUCLEI provides detailed severity information in its output.
        if tool == "NUCLEI" and findings:
            for finding in findings:
                finding_str = str(finding).lower()
                if "[critical]" in finding_str or "severity: critical" in finding_str:
                    severity_counter["critical"] += 1
                elif "[high]" in finding_str or "severity: high" in finding_str:
                    severity_counter["high"] += 1
                elif "[medium]" in finding_str or "severity: medium" in finding_str:
                    severity_counter["medium"] += 1
                else:
                    severity_counter["low"] += 1
        else:
            # Standardized severity mapping for other tools, ensuring that even if a tool does not provide explicit severity levels, we can still categorize its findings appropriately.
            severity = result.get("severity", "low").lower()
            if severity == "weak":
                severity = "medium"
            if severity == "info":
                severity = "low"
                
            # If the tool does not provide a list of findings, we still increment the severity counter to reflect that the tool was executed and produced output, even if no specific findings were identified.
            count = len(findings) if isinstance(findings, list) else 1
            severity_counter[severity] += max(1, count)

    chart_dir = Path("/tmp/pentest_charts")
    chart_dir.mkdir(exist_ok=True)
    severity_chart = chart_dir / "severity_chart.png"

    # Filter to include only severity levels that have findings, ensuring that the pie chart accurately reflects the distribution of vulnerabilities without cluttering it with empty categories.
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
        tool = str(result.get("tool", "unknown")).upper()
        findings = result.get("findings", [])
        findings_count = len(findings) if isinstance(findings, list) else 1
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