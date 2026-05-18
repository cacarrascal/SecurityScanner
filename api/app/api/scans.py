"""Endpoints de escaneo — streaming SSE (Vercel friendly).

Cada endpoint corre el pipeline DENTRO de la request y va enviando eventos
(progress, log, status, result) por Server-Sent Events.

Para repos Git: en vez de `git clone` (Vercel no incluye el binario git en su
runtime Python), descargamos el tarball directamente desde codeload.github.com.
Solo soporta repos públicos de GitHub.
"""
from __future__ import annotations

import asyncio
import re
import shutil
import tarfile
import uuid
from pathlib import Path

import httpx
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from loguru import logger

from app.config import MAX_UPLOAD_SIZE
from app.models.schemas import GitScanRequest, ScanType, URLScanRequest
from app.services.events import EventStream
from app.services.orchestrator import run_project_scan, run_url_scan
from app.utils.security import is_safe_url, safe_extract_zip, safe_extract_tar, sanitize_filename
from app.utils.workspace import workspace


router = APIRouter(prefix="/api/scans", tags=["scans"])

SSE_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    "Content-Type": "text/event-stream",
    "X-Accel-Buffering": "no",
}

MAX_REPO_SIZE = 100 * 1024 * 1024  # 100 MB tarball comprimido

GITHUB_URL_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def _parse_github_url(url: str) -> tuple[str, str]:
    m = GITHUB_URL_RE.match(url.strip())
    if not m:
        raise HTTPException(
            400,
            "Solo se soportan repos públicos de GitHub "
            "(formato: https://github.com/owner/repo). "
            "Vercel no permite git CLI en serverless.",
        )
    return m.group("owner"), m.group("repo")


async def _download_github_tarball(owner: str, repo: str, branch: str, dest: Path, events: EventStream) -> int:
    """Baja el tarball de GitHub a `dest` (archivo). Devuelve bytes descargados."""
    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}"
    events.log(f"Descargando {url}")

    total = 0
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
            if resp.status_code == 404:
                raise HTTPException(
                    404,
                    f"Repo o branch no encontrado: {owner}/{repo}@{branch}",
                )
            if resp.status_code != 200:
                raise HTTPException(
                    400,
                    f"GitHub devolvió HTTP {resp.status_code} al descargar el repo",
                )

            with dest.open("wb") as f:
                async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                    total += len(chunk)
                    if total > MAX_REPO_SIZE:
                        raise HTTPException(
                            413,
                            f"Repo excede {MAX_REPO_SIZE // (1024 * 1024)} MB (tarball comprimido)",
                        )
                    f.write(chunk)

    events.log(f"✓ Tarball descargado: {total // 1024} KB", "success")
    return total


def _extract_tarball_flat(tar_path: Path, dest: Path, events: EventStream) -> int:
    """Extrae el tarball aplanando el directorio raíz que GitHub agrega."""
    extracted = 0
    dest_resolved = dest.resolve()
    with tarfile.open(tar_path, "r:gz") as tf:
        members = tf.getmembers()
        if not members:
            return 0

        root_prefix = members[0].name.split("/")[0] + "/"

        for member in members:
            if member.name == root_prefix.rstrip("/"):
                continue
            rel = member.name[len(root_prefix):] if member.name.startswith(root_prefix) else member.name
            if not rel:
                continue
            target = dest / rel
            try:
                target.resolve().relative_to(dest_resolved)  # anti path traversal
            except ValueError:
                continue
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted_file = tf.extractfile(member)
            if extracted_file is None:
                continue
            with target.open("wb") as f:
                shutil.copyfileobj(extracted_file, f)
            extracted += 1

    events.log(f"✓ {extracted} archivos extraídos", "success")
    return extracted


def _sse_response(events: EventStream, runner) -> StreamingResponse:
    asyncio.create_task(_safe_runner(events, runner))
    return StreamingResponse(events.iter_sse(), headers=SSE_HEADERS, media_type="text/event-stream")


async def _safe_runner(events: EventStream, runner) -> None:
    try:
        await runner()
    except Exception as e:
        logger.exception("Error inesperado en runner SSE")
        try:
            events.error(str(e))
        except Exception:
            pass
    finally:
        events.close()


@router.post("/git")
async def scan_git(request: GitScanRequest):
    """Descarga repo de GitHub vía tarball y emite progreso por SSE."""
    safe, reason = is_safe_url(request.repo_url)
    if not safe:
        raise HTTPException(400, f"Repo URL bloqueada: {reason}")

    owner, repo = _parse_github_url(request.repo_url)
    branch = (request.branch or "main").strip() or "main"

    events = EventStream()
    scan_id = str(uuid.uuid4())

    async def runner():
        with workspace() as ws:
            tar_path = ws.base / "repo.tar.gz"
            try:
                await _download_github_tarball(owner, repo, branch, tar_path, events)
                _extract_tarball_flat(tar_path, ws.source, events)
                tar_path.unlink(missing_ok=True)
            except HTTPException as e:
                events.status("failed", str(e.detail))
                events.error(str(e.detail))
                return
            except Exception as e:
                events.status("failed", f"Error obteniendo repo: {e}")
                events.error(f"Error obteniendo repo: {e}")
                return

            result = await run_project_scan(events, ws, scan_id, request.repo_url, ScanType.GIT)
            events.result(result.model_dump(mode="json"))

    return _sse_response(events, runner)


@router.post("/upload")
async def upload_project(file: UploadFile = File(...)):
    """Sube ZIP/archivo y emite progreso por SSE."""
    if not file.filename:
        raise HTTPException(400, "Archivo sin nombre")

    safe_name = sanitize_filename(file.filename)

    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > MAX_UPLOAD_SIZE:
            raise HTTPException(413, f"Archivo excede {MAX_UPLOAD_SIZE} bytes")
        chunks.append(chunk)
    if total == 0:
        raise HTTPException(400, "Archivo vacío")
    blob = b"".join(chunks)

    events = EventStream()
    scan_id = str(uuid.uuid4())

    async def runner():
        with workspace() as ws:
            archive_path = ws.base / safe_name
            try:
                archive_path.write_bytes(blob)
                events.log(f"Archivo recibido ({total} bytes): {safe_name}")

                ext = archive_path.suffix.lower()
                if ext == ".zip":
                    files_count = safe_extract_zip(archive_path, ws.source)
                    archive_path.unlink(missing_ok=True)
                elif ext in (".tar", ".gz", ".tgz") or ".tar." in safe_name:
                    files_count = safe_extract_tar(archive_path, ws.source)
                    archive_path.unlink(missing_ok=True)
                else:
                    target = ws.source / safe_name
                    shutil.move(str(archive_path), str(target))
                    files_count = 1
                events.log(f"✓ {files_count} archivos extraídos", "success")
            except Exception as e:
                events.status("failed", f"Error procesando archivo: {e}")
                events.error(f"Error procesando archivo: {e}")
                return

            result = await run_project_scan(events, ws, scan_id, safe_name, ScanType.FILE)
            events.result(result.model_dump(mode="json"))

    return _sse_response(events, runner)


@router.post("/url")
async def scan_url(request: URLScanRequest):
    """Escanea URL pública y emite progreso por SSE."""
    safe, reason = is_safe_url(request.url)
    if not safe:
        raise HTTPException(400, f"URL bloqueada: {reason}")

    events = EventStream()
    scan_id = str(uuid.uuid4())

    async def runner():
        result = await run_url_scan(events, scan_id, request.url, deep=request.deep_scan)
        events.result(result.model_dump(mode="json"))

    return _sse_response(events, runner)
