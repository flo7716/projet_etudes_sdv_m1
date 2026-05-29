#!/usr/bin/env python3
"""
Interactive CLI for Pentest Toolbox
Provides a user-friendly menu-driven interface to run security testing tools
"""

from app.modules.ettercap import run_ettercap, run_ettercap_interactive
from app.modules.msfvenom import run_msfvenom, run_msfvenom_interactive
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
import sys
import os
from datetime import datetime, timezone

from app.modules.gobuster import run_gobuster, run_gobuster_interactive
from app.modules.hydra import run_hydra, run_hydra_interactive
from app.modules.john import run_john, run_john_interactive
from app.modules.nikto import run_nikto, run_nikto_interactive
from app.modules.nmap import run_nmap, run_nmap_interactive
from app.modules.sqlmap import run_sqlmap, run_sqlmap_interactive
from app.modules.searchsploit import run_searchsploit, run_searchsploit_interactive
from app.modules.ffuf import run_ffuf, run_ffuf_interactive
from app.modules.report import generate_pdf_report


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
        result = interactive_func()
        console.print(f"[green]✓ {label} completed[/green]")
        console.print(result)
    except Exception as e:
        console.print(f"[red]✗ Error: {str(e)}[/red]")



def run_pipeline_interactive():
    """Interactive pipeline execution"""
    console.print("\n[bold cyan]=== PENTEST PIPELINE ===[/bold cyan]")
    
    target = questionary.text(
        "Enter target host/URL:",
        validate=lambda x: len(x) > 0
    ).ask()
    
    tests = questionary.checkbox(
        "Select tests to run:",
        choices=["nmap", "nikto", "gobuster", "sqlmap", "hydra", "john", "ettercap", "searchsploit", "ffuf"],
        validate=lambda x: len(x) > 0
    ).ask()

    # Afficher les options en fonction du ou des tests sélectionnés et passer au suivant une fois les options renseignées
    for test in tests:
        console.print(f"\n[bold yellow]Options for {test.upper()}:[/bold yellow]")
        if test == "nmap":
            options = questionary.text(
                "Additional nmap options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "nikto":
            options = questionary.text(
                "Additional nikto options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "gobuster":
            options = questionary.text(
                "Additional gobuster options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "sqlmap":
            options = questionary.text(
                "Additional sqlmap options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "hydra":
            options = questionary.text(
                "Additional hydra options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "john":
            options = questionary.text(
                "Additional john options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "ettercap":
            options = questionary.text(
                "Additional ettercap options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "searchsploit":
            options = questionary.text(
                "Additional searchsploit options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "ffuf":
            options = questionary.text(
                "Additional ffuf options (leave empty for defaults):",
                default=""
            ).ask()
        else:       
            options = ""
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
            if test == "nmap":
                results["nmap"] = run_nmap(target, "")
            elif test == "nikto":
                results["nikto"] = run_nikto(target, "")
            elif test == "gobuster":
                results["gobuster"] = run_gobuster(target, None, "")
            elif test == "sqlmap":
                results["sqlmap"] = run_sqlmap(target, "")
            elif test == "hydra":
                results["hydra"] = run_hydra(target, "root", None, "")
            elif test == "john":
                results["john"] = {"note": "john requires a hash file; skipped in pipeline unless provided separately"}
            elif test == "ettercap":
                results["ettercap"] = run_ettercap(target, "")
            elif test == "searchsploit":
                results["searchsploit"] = run_searchsploit(target, "")
            else:
                results[test] = {"error": "Unknown test selected"}
        except Exception as e:
            results[test] = {"error": str(e)}

    report_title = f"Pentest report for {target} ({timestamp})"
    try:
        result = generate_pdf_report(
            results,
            report_title,
            output_file,
            copy_to_host=copy_to_host,
        )
        console.print(f"[green]✓ Pipeline completed[/green]")
        console.print(f"[green]Report saved to: {output_file}[/green]")
        console.print(result)
    except Exception as e:
        console.print(f"[red]✗ Error: {str(e)}[/red]")


def display_tools_info():
    """Display information about available tools"""
    console.print("\n[bold cyan]=== AVAILABLE TOOLS ===[/bold cyan]")
    
    table = Table(title="Pentest Tools", show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan")
    table.add_column("Description", style="green")
    
    tools = [
        ("NMAP", "Network mapping and port scanning"),
        ("HYDRA", "Brute-force attack tool"),
        ("JOHN", "Password cracking utility"),
        ("NIKTO", "Web server scanner"),
        ("GOBUSTER", "Directory/file brute-forcing"),
        ("SQLMAP", "SQL injection detection"),
        ("ETTERCAP", "Network discovery and MITM attacks"),
        ("MSFVENOM", "Payload generation"),
        ("SEARCHSPLOIT", "Vulnerability search"),
        ("FFUF", "Fast web fuzzer"),
        ("PIPELINE", "Run multiple tests & generate report"),
    ]
    
    for tool, desc in tools:
        table.add_row(tool, desc)
    
    console.print(table)


def main():
    """Main interactive CLI loop"""
    display_banner()
    
    while True:
        console.print()
        choice = questionary.select(
            "Select a tool to run:",
            choices=[
                "🔍 NMAP - Network Scanning",
                "🔓 HYDRA - Brute-Force",
                "🔑 JOHN - Password Cracking",
                "🕷️  NIKTO - Web Scanning",
                "📁 GOBUSTER - Directory Scanning",
                "🗄️  SQLMAP - SQL Injection",
                "🕸️  ETTERCAP - Network Discovery",
                "💀 MSFVENOM - Payload Generation",
                "🔎 SEARCHSPLOIT - Vulnerability Search",
                "📊 PIPELINE - Run Full Pipeline",
                "🕷️  FFUF - Web Fuzzing",
                "ℹ️  Information",
                "❌ Exit",
            ],
            pointer="→"
        ).ask()
        
        if "NMAP" in choice:
            run_interactive_tool(run_nmap_interactive, "Nmap scan")
        elif "HYDRA" in choice:
            run_interactive_tool(run_hydra_interactive, "Hydra scan")
        elif "JOHN" in choice:
            run_interactive_tool(run_john_interactive, "John scan")
        elif "NIKTO" in choice:
            run_interactive_tool(run_nikto_interactive, "Nikto scan")
        elif "GOBUSTER" in choice:
            run_interactive_tool(run_gobuster_interactive, "Gobuster scan")
        elif "SQLMAP" in choice:
            run_interactive_tool(run_sqlmap_interactive, "Sqlmap scan")
        elif "PIPELINE" in choice:
            run_pipeline_interactive()
        elif "ETTERCAP" in choice:
            run_interactive_tool(run_ettercap_interactive, "Ettercap scan")
        elif "MSFVENOM" in choice:
            run_interactive_tool(run_msfvenom_interactive, "Msfvenom generation")
        elif "SEARCHSPLOIT" in choice:
            run_interactive_tool(run_searchsploit_interactive, "Searchsploit scan")
        elif "FFUF" in choice:
            run_interactive_tool(run_ffuf_interactive, "Ffuf scan")
        elif "Information" in choice:
            display_tools_info()
        elif "Exit" in choice:
            console.print("\n[green]Goodbye![/green]\n")
            break
        
        continue_choice = questionary.confirm(
            "\nRun another tool?",
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
