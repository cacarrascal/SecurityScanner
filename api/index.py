"""Entrypoint para Vercel Python Function.

Vercel no agrega la carpeta /api al sys.path automáticamente, así que la
añadimos para que `from app.main import app` pueda encontrar el paquete
`api/app/`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import app  # noqa: E402

__all__ = ["app"]
