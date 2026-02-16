from toolbox.workers.celery_app import celery
from toolbox.modules.scanning.openvas import OpenVASScanner


@celery.task
def run_openvas_scan(target_ip):

    scanner = OpenVASScanner()

    task_id = scanner.scan(target_ip)

    return {
        "status": "started",
        "task_id": task_id,
        "target": target_ip
    }
