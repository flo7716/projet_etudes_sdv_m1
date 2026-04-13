from fastapi import FastAPI

from toolbox.api.routes import scans, tasks, health

app = FastAPI(title="Pentest Toolbox API")

app.include_router(health.router)
app.include_router(scans.router)
app.include_router(tasks.router)