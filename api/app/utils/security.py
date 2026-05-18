"""Helpers de seguridad: SSRF, path traversal, sanitización."""
from __future__ import annotations

import ipaddress
import socket
import zipfile
import tarfile
from pathlib import Path
from urllib.parse import urlparse

from app.config import BLOCKED_IP_RANGES, MAX_UPLOAD_SIZE


def is_safe_url(url: str) -> tuple[bool, str]:
    """Anti-SSRF: bloquea IPs privadas y esquemas no http/https."""
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"URL inválida: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Esquema no permitido: {parsed.scheme}"

    if not parsed.hostname:
        return False, "URL sin hostname"

    # Resolver hostname a IP
    try:
        addr_info = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        return False, f"No se puede resolver: {parsed.hostname}"

    blocked_networks = [ipaddress.ip_network(r) for r in BLOCKED_IP_RANGES]

    for info in addr_info:
        try:
            ip = ipaddress.ip_address(info[4][0])
            for network in blocked_networks:
                if ip in network:
                    return False, f"IP privada/local bloqueada: {ip}"
        except ValueError:
            continue

    return True, ""


def is_safe_path(base: Path, target: Path) -> bool:
    """Anti path traversal."""
    try:
        base_resolved = base.resolve()
        target_resolved = target.resolve()
        return str(target_resolved).startswith(str(base_resolved))
    except Exception:
        return False


def safe_extract_zip(zip_path: Path, destination: Path) -> int:
    """Extrae ZIP con protección contra path traversal y zip bombs."""
    destination.mkdir(parents=True, exist_ok=True)
    extracted = 0
    total_size = 0
    MAX_TOTAL = MAX_UPLOAD_SIZE * 3  # ratio máximo de compresión

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            target = destination / info.filename

            # Bloqueo path traversal
            if not is_safe_path(destination, target):
                continue

            # Anti zip bomb
            total_size += info.file_size
            if total_size > MAX_TOTAL:
                raise ValueError(f"ZIP excede tamaño descomprimido máximo")

            # Skip directorios
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                # Lee en chunks para evitar OOM
                while chunk := src.read(64 * 1024):
                    dst.write(chunk)
            extracted += 1

    return extracted


def safe_extract_tar(tar_path: Path, destination: Path) -> int:
    """Extrae TAR con protección contra path traversal."""
    destination.mkdir(parents=True, exist_ok=True)
    extracted = 0

    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            target = destination / member.name
            if not is_safe_path(destination, target):
                continue
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            tf.extract(member, destination, set_attrs=False)
            extracted += 1

    return extracted


def sanitize_filename(name: str) -> str:
    """Elimina chars peligrosos del nombre de archivo."""
    keep = "._-"
    return "".join(c if (c.isalnum() or c in keep) else "_" for c in name)[:200]
