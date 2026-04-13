from fastapi import APIRouter
from toolbox.workers.tasks.nmap_tasks import run_nmap

router = APIRouter()


@router.post("/scan/nmap")
def scan_nmap(target: str):

    task = run_nmap.delay(target)

    return {
        "task_id": task.id,
        "status": "started"
    }