from toolbox.workers.celery_app import celery
from toolbox.modules.exploitation.hydra import HydraBruteforce


@celery.task(name="tasks.run_hydra")
def run_hydra(target: str, service: str, user: str, wordlist: str):

    scanner = HydraBruteforce(
        target=target,
        service=service,
        user=user,
        wordlist=wordlist
    )

    return scanner.run()