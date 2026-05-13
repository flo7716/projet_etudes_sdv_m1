from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.routes import router

app = FastAPI()

app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).resolve().parent / "static"),
    name="static",
)

@app.get("/", response_class=FileResponse)
def root():
    return Path(__file__).resolve().parent / "static" / "index.html"

app.include_router(router, prefix="/api")