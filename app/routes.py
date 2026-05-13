from fastapi import APIRouter
from app.modules.nmap import run_nmap
from app.modules.hydra import run_hydra
from app.modules.john import run_john
from app.modules.openvas import run_openvas

router = APIRouter()


@router.get("/")
def home():
    return {"message": "Pentest Toolbox"}


@router.get("/nmap")
def nmap_scan(target: str, options: str = ""):
    return run_nmap(target, options)


@router.get("/hydra")
def hydra_scan(target: str, user: str = "root", passlist: str = "/usr/share/wordlists/rockyou.txt"):
    return run_hydra(target, user, passlist)


@router.get("/john")
def john_scan(hash_file: str, wordlist: str = "/usr/share/john/password.lst"):
    return run_john(hash_file, wordlist)

@router.get("/openvas")
def openvas_scan(target: str):
    from app.modules.openvas import run_openvas
    return run_openvas(target)

@router.get("/nikto")
def nikto_scan(target: str):
    from app.modules.nikto import run_nikto
    return run_nikto(target)

@router.get("/gobuster")
def gobuster_scan(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt"):
    from app.modules.gobuster import run_gobuster
    return run_gobuster(target, wordlist)
