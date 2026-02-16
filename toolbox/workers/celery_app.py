from celery import Celery
import os

celery = Celery(
    "toolbox",
    broker=os.getenv("REDIS_URL", "redis://redis:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://redis:6379/0")
)

celery.autodiscover_tasks(["toolbox.workers.tasks"])
