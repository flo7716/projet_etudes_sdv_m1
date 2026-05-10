from fastapi import APIRouter
from app.modules.nmap import run_nmap
from app.modules.hydra import run_hydra
from app.modules.john import run_john

router = APIRouter()


@router.get("/")
def home():
    return {"message": "Pentest Toolbox"}


@router.get("/nmap")
def nmap_scan(target: str):

    result = run_nmap(target)

    return result


@router.get("/hydra")
def hydra_scan(target: str):
    return run_hydra(target)


@router.get("/john")
def john_scan(hash_file: str):
    return run_john(hash_file)

@router.get("/nikto")
def nikto_scan(target: str):
    from app.modules.nikto import run_nikto
    return run_nikto(target)

@router.get("/gobuster")
def gobuster_scan(target: str):
    from app.modules.gobuster import run_gobuster
    return run_gobuster(target)
