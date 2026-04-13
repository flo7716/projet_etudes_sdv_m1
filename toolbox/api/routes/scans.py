from fastapi import APIRouter
from toolbox.workers.tasks.nmap_tasks import run_nmap
from toolbox.workers.tasks.hydra_tasks import run_hydra
from pydantic import BaseModel

router = APIRouter()


@router.post("/scan/nmap")
def scan_nmap(target: str):

    task = run_nmap.delay(target)

    return {
        "task_id": task.id,
        "status": "started"
    }

class HydraRequest(BaseModel):
    target: str
    service: str = "ssh"
    user: str = "root"
    wordlist: str = "/wordlists/rockyou.txt"

@router.post("/scan/hydra")
def scan_hydra(request: HydraRequest):

    task = run_hydra.delay(
        target=request.target,
        service=request.service,
        user=request.user,
        wordlist=request.wordlist
    )

    return {
        "task_id": task.id,
        "status": "started"
    }