#!/usr/bin/env python3
"""
Interactive CLI for Pentest Toolbox
Provides a user-friendly menu-driven interface to run security testing tools
"""

import sys
import os
from datetime import datetime, timezone
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Imports des modules de la boîte à outils
from app.modules.aircrack_ng import run_aircrack_ng, run_aircrack_ng_interactive
from app.modules.nuclei import run_nuclei, run_nuclei_interactive
from app.modules.msfvenom import run_msfvenom, run_msfvenom_interactive
from app.modules.gobuster import run_gobuster, run_gobuster_interactive
from app.modules.hydra import run_hydra, run_hydra_interactive
from app.modules.john import run_john, run_john_interactive
from app.modules.nikto import run_nikto, run_nikto_interactive
from app.modules.nmap import run_nmap, run_nmap_interactive
from app.modules.sqlmap import run_sqlmap, run_sqlmap_interactive
from app.modules.searchsploit import run_searchsploit, run_searchsploit_interactive
from app.modules.ffuf import run_ffuf, run_ffuf_interactive
from app.modules.sslyze import run_sslyze, run_sslyze_interactive
from app.modules.clamscan import run_clamscan, run_clamscan_interactive
from app.modules.tshark import run_tshark, run_tshark_interactive
from app.modules.report import generate_pdf_report, normalize_tool_result

console = Console()


def display_banner():
    """Display welcome banner"""
    banner = Panel(
        "[bold red]SWISSKNIFE[/bold red]\n[green]Interactive CLI Interface[/green]",
        title="[bold]Welcome[/bold]",
        border_style="red",
    )
    console.print(banner)


def run_interactive_tool(interactive_func, label):
    try:
        console.print(f"\n[bold blue]▶ Starting {label}...[/bold blue]")
        result = interactive_func()
        console.print(f"[green]✓ {label} completed[/green]")
        console.print(result)
    except Exception as e:
        console.print(f"[red]✗ Error while running {label}: {str(e)}[/red]")


def run_pipeline_interactive():
    """Interactive pipeline execution (Cleaned from slow/unautomated tools)"""
    console.print("\n[bold cyan]=== PENTEST AUTOMATED PIPELINE ===[/bold cyan]")
    
    target = questionary.text(
        "Enter target host/URL:",
        validate=lambda x: len(x) > 0
    ).ask()
    
    tests = questionary.checkbox(
        "Select automated tests to run:",
        choices=[
            "nmap", 
            "sslyze", 
            "nikto", 
            "gobuster", 
            "nuclei", 
            "ffuf", 
            "sqlmap"
        ],
        validate=lambda x: len(x) > 0
    ).ask()

    pipeline_args = {}

    for test in tests:
        console.print(f"\n[bold yellow]Options for {test.upper()}:[/bold yellow]")
        pipeline_args[test] = {"options": ""}

        if test == "nmap":
            pipeline_args[test]["options"] = questionary.text(
                "Additional nmap options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "sslyze":
            pipeline_args[test]["options"] = questionary.text(
                "Additional sslyze options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "nikto":
            pipeline_args[test]["options"] = questionary.text(
                "Additional nikto options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "gobuster":
            pipeline_args[test]["options"] = questionary.text(
                "Additional gobuster options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "nuclei":
            pipeline_args[test]["options"] = questionary.text(
                "Additional nuclei options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "ffuf":
            pipeline_args[test]["wordlist"] = questionary.text(
                "Wordlist path:",
                default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            ).ask()
            pipeline_args[test]["options"] = questionary.text(
                "Additional ffuf options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "sqlmap":
            pipeline_args[test]["options"] = questionary.text(
                "Additional sqlmap options (e.g. --batch --crawl=2):",
                default="--batch"
            ).ask()
        
        console.print(f"[green]Options for {test.upper()} set[/green]")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    default_filename = f"report_{timestamp}.pdf"
    output_file = questionary.text(
        "Output PDF filename:",
        default=default_filename
    ).ask()
    
    if not output_file or not output_file.strip():
        output_file = default_filename
    elif not output_file.lower().endswith(".pdf"):
        output_file = f"{output_file}.pdf"
    
    copy_to_host = questionary.confirm(
        "Copy PDF to host mount?",
        default=False
    ).ask()
    
    console.print(f"\n[yellow]Running pipeline with tests: {', '.join(tests)}[/yellow]")
    results = {}
    
    for test in tests:
        try:
            console.print(f"\n[bold blue]▶ Running {test.upper()}...[/bold blue]")
            options = pipeline_args.get(test, {}).get("options", "")
            raw_result = None

            if test == "nmap":
                raw_result = run_nmap(target, options)
            elif test == "sslyze":
                raw_result = run_sslyze(target, options)
            elif test == "nikto":
                raw_result = run_nikto(target, options)
            elif test == "gobuster":
                raw_result = run_gobuster(target, None, options)
            elif test == "nuclei":
                raw_result = run_nuclei(target, options)
            elif test == "ffuf":
                wordlist = pipeline_args.get(test, {}).get("wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
                raw_result = run_ffuf(target, wordlist, options)
            elif test == "sqlmap":
                if "--batch" not in options:
                    options += " --batch"
                raw_result = run_sqlmap(target, options, interactive=False)

            results[test] = normalize_tool_result(test, raw_result, target)
            console.print(f"[green]✓ {test.upper()} completed[/green]")
        except Exception as e:
            results[test] = {
                "tool": test, 
                "error": str(e), 
                "summary": str(e), 
                "findings": [], 
                "severity": "medium", 
                "recommendations": [], 
                "raw_output": str(raw_result) if 'raw_result' in locals() else ""
            }
            console.print(f"[red]✗ {test.upper()} failed: {str(e)}[/red]")

    report_title = f"Pentest report for {target} ({timestamp})"
    try:
        result = generate_pdf_report(
            results,
            report_title,
            output_file,
            copy_to_host=copy_to_host,
        )
        console.print(f"\n[green]✓ Pipeline completed[/green]")
        console.print(f"[green]Report saved to: {output_file}[/green]")
        console.print(result)
    except Exception as e:
        console.print(f"[red]✗ Error during report generation: {str(e)}[/red]")


def display_tools_info():
    """Display information about available tools and execution modes"""
    console.print("\n[bold cyan]=== AVAILABLE TOOLS MATRIX ===[/bold cyan]")
    
    table = Table(title="Pentest Tools Directory", show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan")
    table.add_column("Supported Modes", style="yellow")
    table.add_column("Description", style="green")
    
    tools = [
        ("NMAP", "Pipeline & Standalone", "Network mapping and port scanning"),
        ("SSLYZE", "Pipeline & Standalone", "SSL/TLS configuration and certificate analysis"),
        ("NIKTO", "Pipeline & Standalone", "Web server misconfiguration scanner"),
        ("GOBUSTER", "Pipeline & Standalone", "Directory/file brute-forcing enumeration"),
        ("NUCLEI", "Pipeline & Standalone", "Template-based fast vulnerability scanning"),
        ("FFUF", "Pipeline & Standalone", "Web fuzzing and hidden endpoint discovery"),
        ("SQLMAP", "Pipeline & Standalone", "Automated SQL injection detection and exploitation"),
        ("HYDRA", "Standalone Only", "Network brute-force attack simulation (Slow for pipeline)"),
        ("JOHN", "Standalone Only", "Password hashing recovery (Requires hardware resources)"),
        ("AIRCRACK-NG", "Standalone Only", "Wireless 802.11 network auditing and key cracking"),
        ("MSFVENOM", "Standalone Only", "Payload generation and shellcode compilation"),
        ("SEARCHSPLOIT", "Standalone Only", "Local Exploit-DB archive query utility"),
        ("CLAMAV", "Standalone Only", "Antivirus signature-based analysis"),
        ("TSHARK", "Standalone Only", "Command-line packet capture and deep traffic inspection"),
    ]
    
    for tool, mode, desc in tools:
        table.add_row(tool, mode, desc)
    
    console.print(table)


def main():
    """Main interactive CLI loop"""
    display_banner()
    
    while True:
        console.print()
        # Utilisation de libellés calibrés avec une tabulation fixe après les émojis
        choice = questionary.select(
            "Select an operation or tool to run:",
            choices=[
                "📊  PIPELINE     - Run Full Automated Pipeline",
                "🔍  NMAP         - Network Scanning [Pipeline & Standalone]",
                "🔒  SSLYZE       - SSL/TLS Analysis [Pipeline & Standalone]",
                "🕷️   NIKTO        - Web Scanning [Pipeline & Standalone]",
                "📁  GOBUSTER     - Directory Scanning [Pipeline & Standalone]",
                "🧪  NUCLEI       - Vulnerability Scanning [Pipeline & Standalone]",
                "🕷️   FFUF         - Web Fuzzing [Pipeline & Standalone]",
                "🗄️   SQLMAP       - SQL Injection [Pipeline & Standalone]",
                "🔓  HYDRA        - Brute-Force [Standalone Only]",
                "🔑  JOHN         - Password Cracking [Standalone Only]",
                "🛜  AIRCRACK-NG  - Wireless Testing [Standalone Only]",
                "💀  MSFVENOM     - Payload Generation [Standalone Only]",
                "🔎  SEARCHSPLOIT - Vulnerability Search [Standalone Only]",
                "🔍  CLAMAV       - Antivirus Scan [Standalone Only]",
                "🦈  TSHARK       - Packet Analysis [Standalone Only]",
                "ℹ️   INFO         - Information Matrix",
                "❌  EXIT         - Exit",
            ],
            pointer="→"
        ).ask()
        
        if "PIPELINE" in choice:
            run_pipeline_interactive()
        elif "NMAP" in choice:
            run_interactive_tool(run_nmap_interactive, "Nmap scan")
        elif "SSLYZE" in choice:
            run_interactive_tool(run_sslyze_interactive, "Sslyze scan")
        elif "NIKTO" in choice:
            run_interactive_tool(run_nikto_interactive, "Nikto scan")
        elif "GOBUSTER" in choice:
            run_interactive_tool(run_gobuster_interactive, "Gobuster scan")
        elif "NUCLEI" in choice:
            run_interactive_tool(run_nuclei_interactive, "Nuclei scan")
        elif "FFUF" in choice:
            run_interactive_tool(run_ffuf_interactive, "Ffuf scan")
        elif "SQLMAP" in choice:
            run_interactive_tool(run_sqlmap_interactive, "Sqlmap scan")
        elif "HYDRA" in choice:
            run_interactive_tool(run_hydra_interactive, "Hydra scan")
        elif "JOHN" in choice:
            run_interactive_tool(run_john_interactive, "John scan")
        elif "AIRCRACK-NG" in choice:
            run_interactive_tool(run_aircrack_ng_interactive, "Aircrack-ng scan")
        elif "MSFVENOM" in choice:
            run_interactive_tool(run_msfvenom_interactive, "Msfvenom generation")
        elif "SEARCHSPLOIT" in choice:
            run_interactive_tool(run_searchsploit_interactive, "Searchsploit scan")
        elif "TSHARK" in choice:
            from app.modules.tshark import run_tshark_interactive
            run_interactive_tool(run_tshark_interactive, "Tshark analysis")
        elif "CLAMAV" in choice:
            from app.modules.clamscan import run_clamscan_interactive
            run_interactive_tool(run_clamscan_interactive, "Clamscan analysis")
        elif "INFO" in choice:
            display_tools_info()
        elif "EXIT" in choice:
            console.print("\n[green]Goodbye![/green]\n")
            break
        
        continue_choice = questionary.confirm(
            "\nReturn to main menu?",
            default=True
        ).ask()
        
        if not continue_choice:
            console.print("\n[green]Goodbye![/green]\n")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted by user[/yellow]\n")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {str(e)}[/red]\n")
        sys.exit(1)