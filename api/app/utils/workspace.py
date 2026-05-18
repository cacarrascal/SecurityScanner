"""Workspace efímero para serverless (Vercel).

Vive solo el tiempo de la request: se crea en /tmp, se usa, y se borra al final
con el context manager. No hay manager global ni cleanup loop porque en
serverless cada invocación es un contenedor nuevo y /tmp se descarta.
"""
from __future__ import annotations

import shutil
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class Workspace:
    def __init__(self, base: Path) -> None:
        self.id = base.name
        self.base = base
        self.source = base / "source"
        self.reports = base / "reports"
        for p in (self.source, self.reports):
            p.mkdir(parents=True, exist_ok=True)

    def cleanup(self) -> None:
        if self.base.exists():
            shutil.rmtree(self.base, ignore_errors=True)


@contextmanager
def workspace() -> Iterator[Workspace]:
    """Crea un workspace en /tmp y lo borra al salir del bloque."""
    base = Path(tempfile.gettempdir()) / f"scan-{uuid.uuid4().hex[:12]}"
    ws = Workspace(base)
    try:
        yield ws
    finally:
        ws.cleanup()
