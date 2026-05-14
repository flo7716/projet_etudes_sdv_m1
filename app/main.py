import argparse
import json

from app.modules.gobuster import run_gobuster
from app.modules.hydra import run_hydra
from app.modules.john import run_john
from app.modules.nikto import run_nikto
from app.modules.nmap import run_nmap
from app.modules.sqlmap import run_sqlmap


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
    else:
        parser.error("Unknown command")
        return 1

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
