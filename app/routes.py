from fastapi import APIRouter
from app.modules.nmap import run_nmap
from app.modules.hydra import run_hydra

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