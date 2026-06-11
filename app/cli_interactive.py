#!/usr/bin/env python3
"""
Interactive CLI for Pentest Toolbox
Provides a user-friendly menu-driven interface to run security testing tools
"""

from app.modules.aircrack_ng import run_aircrack_ng, run_aircrack_ng_interactive
from app.modules.nuclei import run_nuclei, run_nuclei_interactive
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
        choices=["nmap", "nikto", "gobuster", "sqlmap", "hydra", "john", "aircrack_ng", "nuclei", "searchsploit", "ffuf", "sslyze", "tshark", "clamscan"],
        validate=lambda x: len(x) > 0
    ).ask()

    pipeline_args = {}

    # Afficher les options en fonction du ou des tests sélectionnés et passer au suivant une fois les options renseignées
    for test in tests:
        console.print(f"\n[bold yellow]Options for {test.upper()}:[/bold yellow]")
        pipeline_args[test] = {"options": ""}

        if test == "nmap":
            pipeline_args[test]["options"] = questionary.text(
                "Additional nmap options (leave empty for defaults):",
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
        elif test == "sqlmap":
            pipeline_args[test]["options"] = questionary.text(
                "Additional sqlmap options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "hydra":
            pipeline_args[test]["passlist"] = questionary.text(
                "Hydra password list path:",
                default="/usr/share/wordlists/rockyou.txt",
            ).ask()
            pipeline_args[test]["options"] = questionary.text(
                "Additional hydra options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "john":
            pipeline_args[test]["options"] = questionary.text(
                "Additional john options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "aircrack_ng":
            pipeline_args[test]["options"] = questionary.text(
                "Additional aircrack-ng options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "nuclei":
            pipeline_args[test]["options"] = questionary.text(
                "Additional nuclei options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "searchsploit":
            pipeline_args[test]["options"] = questionary.text(
                "Additional searchsploit options (leave empty for defaults):",
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
        elif test == "sslyze":
            pipeline_args[test]["options"] = questionary.text(
                "Additional sslyze options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "tshark":
            pipeline_args[test]["options"] = questionary.text(
                "Additional tshark options (leave empty for defaults):",
                default=""
            ).ask()
        elif test == "clamscan":
            pipeline_args[test]["options"] = questionary.text(
                "Additional clamscan options (leave empty for defaults):",
                default=""
            ).ask()
        else:
            pipeline_args[test]["options"] = ""
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
            options = pipeline_args.get(test, {}).get("options", "")
            raw_result = None

            if test == "nmap":
                raw_result = run_nmap(target, options)
            elif test == "nikto":
                raw_result = run_nikto(target, options)
            elif test == "gobuster":
                raw_result = run_gobuster(target, None, options)
            elif test == "sqlmap":
                raw_result = run_sqlmap(target, options, interactive=True)
                print(f"DEBUG sqlmap raw_result: {repr(raw_result)}")
            elif test == "hydra":
                passlist = pipeline_args.get(test, {}).get("passlist", "/usr/share/wordlists/rockyou.txt")
                raw_result = run_hydra(target, "root", passlist, options)
            elif test == "john":
                raw_result = {"note": "john requires a hash file; skipped in pipeline unless provided separately"}
            elif test == "aircrack_ng":
                raw_result = run_aircrack_ng(target, options)
            elif test == "nuclei":
                raw_result = run_nuclei(target, options)
            elif test == "searchsploit":
                raw_result = run_searchsploit(target, options)
            elif test == "ffuf":
                wordlist = pipeline_args.get(test, {}).get("wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
                raw_result = run_ffuf(target, wordlist, options)
            elif test == "sslyze":
                raw_result = run_sslyze(target, options)
            elif test == "tshark":
                raw_result = run_tshark(target, options)
            elif test == "clamscan":
                raw_result = run_clamscan(target, options)
            else:
                raw_result = {"error": "Unknown test selected"}

            results[test] = normalize_tool_result(test, raw_result, target)  # ← the fix
        except Exception as e:
            import traceback
            traceback.print_exc()
            results[test] = {"tool": test, "error": str(e), "summary": str(e), "findings": [], "severity": "medium", "recommendations": [], "raw_output": str(raw_result) if 'raw_result' in locals() else ""}

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
        import traceback
        traceback.print_exc()
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
        ("AIRCRACK-NG", "Wireless capture and cracking"),
        ("NUCLEI", "Fast vulnerability scanning"),
        ("MSFVENOM", "Payload generation"),
        ("SEARCHSPLOIT", "Vulnerability search"),
        ("FFUF", "Fast web fuzzer"),
        ("SSLYZE", "SSL/TLS configuration analysis"),
        ("CLAMAV", "Antivirus scanning"),
        ("TSHARK", "Packet analysis"),
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
                "  AIRCRACK-NG - Wireless Testing",
                "🧪  NUCLEI - Vulnerability Scanning",
                "💀 MSFVENOM - Payload Generation",
                "🔎 SEARCHSPLOIT - Vulnerability Search",
                "📊 PIPELINE - Run Full Pipeline",
                "🕷️  FFUF - Web Fuzzing",
                "🔒 SSLYZE - SSL/TLS Analysis",
                "🔍 CLAMAV - Antivirus Scan",
                "🦈  TSHARK - Packet Analysis",
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
        elif "AIRCRACK-NG" in choice:
            run_interactive_tool(run_aircrack_ng_interactive, "aircrack-ng scan")
        elif "NUCLEI" in choice:
            run_interactive_tool(run_nuclei_interactive, "nuclei scan")
        elif "MSFVENOM" in choice:
            run_interactive_tool(run_msfvenom_interactive, "Msfvenom generation")
        elif "SEARCHSPLOIT" in choice:
            run_interactive_tool(run_searchsploit_interactive, "Searchsploit scan")
        elif "FFUF" in choice:
            run_interactive_tool(run_ffuf_interactive, "Ffuf scan")
        elif "SSLYZE" in choice:
            run_interactive_tool(run_sslyze_interactive, "Sslyze scan")
        elif "TSHARK" in choice:
            from app.modules.tshark import run_tshark_interactive
            run_interactive_tool(run_tshark_interactive, "Tshark analysis")
        elif "CLAMAV" in choice:
            from app.modules.clamscan import run_clamscan_interactive
            run_interactive_tool(run_clamscan_interactive, "Clamscan analysis")
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
