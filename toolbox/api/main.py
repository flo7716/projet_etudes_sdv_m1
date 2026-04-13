from fastapi import FastAPI
from toolbox.api.routes import scans

app = FastAPI()

app.include_router(scans.router)