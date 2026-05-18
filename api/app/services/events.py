"""Emisor de eventos SSE — sustituye al WebSocket manager.

Productor/consumidor async sobre asyncio.Queue. El orquestador empuja eventos
(log / progress / status / result) y el endpoint los streamea como
Server-Sent Events.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, AsyncIterator


class EventStream:
    _SENTINEL: Any = object()

    def __init__(self) -> None:
        self._queue: asyncio.Queue = asyncio.Queue()
        self._closed = False

    def _push(self, payload: dict) -> None:
        if self._closed:
            return
        payload.setdefault("timestamp", datetime.utcnow().isoformat())
        self._queue.put_nowait(payload)

    def log(self, message: str, level: str = "info") -> None:
        self._push({"type": "log", "level": level, "message": message})

    def progress(self, step: str, progress: float, message: str = "") -> None:
        self._push({
            "type": "progress",
            "step": step,
            "progress": round(progress, 1),
            "message": message,
        })

    def status(self, status: str, message: str = "") -> None:
        self._push({"type": "status", "status": status, "message": message})

    def result(self, payload: dict) -> None:
        self._push({"type": "result", "result": payload})

    def error(self, message: str) -> None:
        self._push({"type": "error", "message": message})

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._queue.put_nowait(self._SENTINEL)

    async def iter_sse(self) -> AsyncIterator[str]:
        """Genera frames SSE (`data: <json>\\n\\n`) hasta que se cierre."""
        while True:
            item = await self._queue.get()
            if item is self._SENTINEL:
                break
            yield f"data: {json.dumps(item, default=str)}\n\n"
