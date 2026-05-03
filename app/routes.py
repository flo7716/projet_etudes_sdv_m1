from fastapi import APIRouter
from app.modules.nmap import run_nmap
from app.modules.hydra import run_hydra

router = APIRouter()


@router.get("/")
def home():
    return {"message": "Pentest Toolbox"}


@router.get("/nmap")
def nmap(target: str):
    return run_nmap(target)


@router.get("/hydra")
def hydra(target: str):
    return run_hydra(target)