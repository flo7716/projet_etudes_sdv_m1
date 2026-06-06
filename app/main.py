import argparse
import json

from app.modules.ffuf import run_ffuf
from app.modules.gobuster import run_gobuster
from app.modules.hydra import run_hydra
from app.modules.john import run_john
from app.modules.msfvenom import run_msfvenom
from app.modules.nikto import run_nikto
from app.modules.nmap import run_nmap
from app.modules.searchsploit import run_searchsploit
from app.modules.sqlmap import run_sqlmap
from app.modules.ettercap import run_ettercap
from app.modules.sslyze import run_sslyze
from app.modules.tshark import run_tshark
from app.modules.clamscan import run_clamscan
from app.modules.ffuf import run_ffuf
from app.modules.report import generate_pdf_report
from datetime import datetime, timezone


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pentest-toolbox",
        description="Pentest Toolbox CLI for nmap, hydra, john, nikto, gobuster and sqlmap",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    nmap_parser = subparsers.add_parser("nmap", help="Run an nmap scan")
    nmap_parser.add_argument("target", help="Scan target (host or IP)")
    nmap_parser.add_argument(
        "--options",
        default="",
        help="Additional nmap options (quoted string)",
    )

    hydra_parser = subparsers.add_parser("hydra", help="Run a hydra brute-force scan")
    hydra_parser.add_argument("target", help="Target host for hydra")
    hydra_parser.add_argument("--user", default="root", help="Username to brute force")
    hydra_parser.add_argument(
        "--passlist",
        default="/usr/share/wordlists/rockyou.txt",
        help="Password list path",
    )
    hydra_parser.add_argument(
        "--options",
        default="",
        help="Additional hydra options (quoted string)",
    )

    john_parser = subparsers.add_parser("john", help="Run john password cracking")
    john_parser.add_argument("hash_file", help="Hash file to crack")
    john_parser.add_argument(
        "--wordlist",
        default="/usr/share/john/password.lst",
        help="Wordlist for john",
    )
    john_parser.add_argument(
        "--options",
        default="",
        help="Additional john options (quoted string)",
    )

    nikto_parser = subparsers.add_parser("nikto", help="Run nikto web scan")
    nikto_parser.add_argument("target", help="Target host or URL for nikto")
    nikto_parser.add_argument(
        "--options",
        default="",
        help="Additional nikto options (quoted string)",
    )

    gobuster_parser = subparsers.add_parser("gobuster", help="Run gobuster directory scan")
    gobuster_parser.add_argument("target", help="Target host or URL for gobuster")
    gobuster_parser.add_argument(
        "--wordlist",
        default="/usr/share/wordlists/dirb/common.txt",
        help="Wordlist for gobuster",
    )
    gobuster_parser.add_argument(
        "--options",
        default="",
        help="Additional gobuster options (quoted string)",
    )

    sqlmap_parser = subparsers.add_parser("sqlmap", help="Run sqlmap injection scan")
    sqlmap_parser.add_argument("target", help="Target URL for sqlmap")
    sqlmap_parser.add_argument(
        "--options",
        default="",
        help="Additional sqlmap options (quoted string)",
    )

    ettercap_parser = subparsers.add_parser("ettercap", help="Run ettercap network scan")
    ettercap_parser.add_argument("target", help="Target host or IP for ettercap")
    ettercap_parser.add_argument(
        "--options",
        default="",
        help="Additional ettercap options (quoted string)",
    )

    msfvenom_parser = subparsers.add_parser("msfvenom", help="Run msfvenom payload generation")
    msfvenom_parser.add_argument(
        "--options",
        default="",
        help="Additional msfvenom options (quoted string)",
    )

    searchsploit_parser = subparsers.add_parser("searchsploit", help="Run searchsploit vulnerability search")
    searchsploit_parser.add_argument("target", help="Search term for searchsploit")
    searchsploit_parser.add_argument(
        "--options",
        default="",
        help="Additional searchsploit options (quoted string)",
    )

    ffuf_parser = subparsers.add_parser("ffuf", help="Run ffuf fuzzing scan")
    ffuf_parser.add_argument("target", help="Target URL for ffuf")
    ffuf_parser.add_argument(
        "--wordlist",
        default="/usr/share/wordlists/rockyou.txt",
        help="Wordlist for ffuf",
    )
    ffuf_parser.add_argument(
        "--options",
        default="",
        help="Additional ffuf options (quoted string)",
    )

    sslyze_parser = subparsers.add_parser("sslyze", help="Run sslyze SSL/TLS scan")
    sslyze_parser.add_argument("target", help="Target host for sslyze")
    sslyze_parser.add_argument(
        "--options",
        default="",
        help="Additional sslyze options (quoted string)",
    )

    tshark_parser = subparsers.add_parser("tshark", help="Run tshark packet analysis")
    tshark_parser.add_argument("target", help="Path to pcap file for tshark")
    tshark_parser.add_argument(
        "--options",
        default="",
        help="Additional tshark options (quoted string)",
    )

    clamscan_parser = subparsers.add_parser("clamscan", help="Run clamscan malware scan")
    clamscan_parser.add_argument("target", help="Path to file or directory for clamscan")
    clamscan_parser.add_argument(
        "--options",
        default="",
        help="Additional clamscan options (quoted string)",
    )



    pipeline_parser = subparsers.add_parser("pipeline", help="Run a pentest pipeline and generate PDF report")
    pipeline_parser.add_argument(
        "--tests",
        nargs="+",
        choices=["nmap", "nikto", "gobuster", "sqlmap", "hydra", "john", "ettercap", "searchsploit", "ffuf"],
        required=True,
        help="List of tests to run (space-separated)",
    )
    pipeline_parser.add_argument("--target", required=True, help="Target host/URL for tests")
    default_report_name = datetime.now(timezone.utc).strftime("report_%Y%m%d_%H%M%SZ.pdf")
    pipeline_parser.add_argument("--out", default=default_report_name, help="Output PDF filename")
    pipeline_parser.add_argument(
        "--copy-to-host",
        action="store_true",
        help="If running in Docker with a bind-mounted host directory, attempt to copy the PDF into the host mount",
    )
    pipeline_parser.add_argument(
        "--host-dest",
        default=None,
        help="Explicit container path that is bind-mounted to the host (e.g. /app). If set, PDF will be copied there.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "nmap":
        result = run_nmap(args.target, args.options)
    elif args.command == "hydra":
        result = run_hydra(args.target, args.user, args.passlist, args.options)
    elif args.command == "john":
        result = run_john(args.hash_file, args.wordlist, args.options)
    elif args.command == "nikto":
        result = run_nikto(args.target, args.options)
    elif args.command == "gobuster":
        result = run_gobuster(args.target, args.wordlist, args.options)
    elif args.command == "sqlmap":
        result = run_sqlmap(args.target, args.options)
    elif args.command == "ettercap":
        result = run_ettercap(args.target, args.options)
    elif args.command == "msfvenom":
        result = run_msfvenom(args.options)
    elif args.command == "searchsploit":
        result = run_searchsploit(args.target, args.options)
    elif args.command == "ffuf":
        result = run_ffuf(args.target, args.wordlist, args.options)
    elif args.command == "sslyze":
        result = run_sslyze(args.target, args.options)
    elif args.command == "tshark":
        result = run_tshark(args.target, args.options)
    elif args.command == "clamscan":
        result = run_clamscan(args.target, args.options)
    elif args.command == "pipeline":
        # run selected tests and aggregate results
        results = {}
        ts = datetime.now(timezone.utc).isoformat()
        for test in args.tests:
            try:
                if test == "nmap":
                    results["nmap"] = run_nmap(args.target, "")
                elif test == "nikto":
                    results["nikto"] = run_nikto(args.target, "")
                elif test == "gobuster":
                    results["gobuster"] = run_gobuster(args.target, None, "")
                elif test == "sqlmap":
                    results["sqlmap"] = run_sqlmap(args.target, "")
                elif test == "hydra":
                    # hydra requires a username and passlist; use defaults
                    results["hydra"] = run_hydra(args.target, "root", "/usr/share/wordlists/rockyou.txt", "")
                elif test == "john":
                    # john typically uses a hash file; record that it's skipped when not provided
                    results["john"] = {"note": "john requires a hash file; skipped in pipeline unless provided separately"}
                elif test == "ettercap":
                    # ettercap requires a target; use the provided target
                    results["ettercap"] = run_ettercap(args.target, args.options)
                elif test == "ffuf":
                    results["ffuf"] = run_ffuf(args.target, "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "")
                elif test == "msfvenom":
                    results["msfvenom"] = run_msfvenom(args.options)
                elif test == "searchsploit":
                    results["searchsploit"] = run_searchsploit(args.target, args.options)
                elif test == "sslyze":
                    results["sslyze"] = run_sslyze(args.target, args.options)
                elif test == "tshark":
                    results["tshark"] = run_tshark(args.target, args.options)
                elif test == "clamscan":
                    results["clamscan"] = run_clamscan(args.target, args.options)
            except Exception as e:
                results[test] = {"error": str(e)}

        report_title = f"Pentest report for {args.target} ({ts})"
        pdf_result = generate_pdf_report(
            results,
            report_title,
            args.out,
            copy_to_host=args.copy_to_host,
            host_dest=args.host_dest,
        )
        result = {"pipeline": results, "report": pdf_result}
    else:
        parser.error("Unknown command")
        return 1

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
