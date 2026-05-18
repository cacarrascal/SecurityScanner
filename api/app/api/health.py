"""Healthchecks."""
import shutil

from fastapi import APIRouter

from app.config import APP_NAME, VERSION


router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
async def health():
    return {"status": "ok", "service": APP_NAME, "version": VERSION}


@router.get("/status")
async def status():
    scanners = {
        "pattern-scanner": True,
        "dependency-scanner": True,
        "complexity-scanner": True,
        "url-scanner": True,
        "bandit": bool(shutil.which("bandit")),
        "pip-audit": bool(shutil.which("pip-audit")),
        "git": bool(shutil.which("git")),
    }
    return {
        "app": APP_NAME,
        "version": VERSION,
        "scanners_available": scanners,
        "runtime": "serverless",
    }
