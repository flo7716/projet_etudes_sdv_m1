from toolbox.workers.celery_app import celery
from toolbox.modules.scanning.nmap import NmapScanner


@celery.task(name="tasks.run_nmap")
def run_nmap(target: str):
    scanner = NmapScanner(target)
    return scanner.run()