"""Wrapper para Bandit — scanner externo OPCIONAL.

Si el binario no está instalado, retorna [] y el pipeline sigue funcionando con
los scanners embebidos. Semgrep y Selenium se eliminaron por no caber en el
límite de 250 MB de Vercel Functions.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

from app.models.schemas import Severity, Vulnerability


class _ExternalBase:
    name = "external"
    binary = ""
    timeout = 50

    def __init__(self, progress_cb: Optional[Callable] = None):
        self.progress_cb = progress_cb

    def _report(self, msg: str, prog: float):
        if self.progress_cb:
            try:
                self.progress_cb(msg, prog)
            except Exception:
                pass
        logger.info(f"[{self.name}] {msg}")

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    async def _run(self, cmd: list[str], cwd: Optional[Path] = None) -> tuple[int, str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
        except asyncio.TimeoutError:
            return -1, "", "timeout"
        except FileNotFoundError:
            return -1, "", "binario no encontrado"
        except Exception as e:
            return -1, "", str(e)


class BanditScanner(_ExternalBase):
    name = "bandit"
    binary = "bandit"
    timeout = 45

    async def scan(self, source: Path) -> list[Vulnerability]:
        if not self.available():
            self._report("Bandit no instalado — saltado", 100)
            return []

        py_files = list(source.rglob("*.py"))
        if not py_files:
            self._report("Sin archivos Python", 100)
            return []

        self._report("Ejecutando Bandit", 10)
        cmd = ["bandit", "-r", str(source), "-f", "json", "-q", "--exit-zero"]
        rc, stdout, stderr = await self._run(cmd)
        if not stdout:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        sev_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        vulns = []
        for r in data.get("results", []):
            try:
                rel = str(Path(r.get("filename", "")).relative_to(source))
            except ValueError:
                rel = r.get("filename", "")
            vulns.append(Vulnerability(
                id=str(uuid.uuid4())[:8],
                rule_id=r.get("test_id", "bandit.unknown"),
                severity=sev_map.get(r.get("issue_severity", "LOW").upper(), Severity.LOW),
                title=r.get("test_name", "Bandit finding"),
                description=r.get("issue_text", ""),
                scanner="bandit",
                file_path=rel,
                line_number=r.get("line_number"),
                code_snippet=(r.get("code") or "")[:300],
                cwe=str(r.get("issue_cwe", {}).get("id", "")) if r.get("issue_cwe") else None,
            ))

        self._report(f"Bandit: {len(vulns)} hallazgos", 100)
        return vulns
