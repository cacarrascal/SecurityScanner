"""FastAPI entry point — versión serverless (Vercel).

Sin lifespan, sin WebSocket: cada request es independiente. El progreso en vivo
viaja por Server-Sent Events dentro del mismo POST.
"""
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.config import APP_NAME, CORS_ORIGINS, VERSION
from app.api import health, scans


logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
    level="INFO",
    colorize=True,
)


app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    description="Security Analyzer — análisis automático sin persistencia (serverless).",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(scans.router)


@app.get("/")
async def root():
    return {
        "name": APP_NAME,
        "version": VERSION,
        "docs": "/docs",
    }
