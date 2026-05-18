"""Métricas de complejidad sin Radon — funciona standalone."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

from app.models.schemas import CodeMetric
from app.utils.files import detect_language, walk_sources


COMPLEXITY_TOKENS = {
    "python": [r"\bif\b", r"\belif\b", r"\bfor\b", r"\bwhile\b", r"\bexcept\b", r"\band\b", r"\bor\b"],
    "javascript": [r"\bif\b", r"\belse if\b", r"\bfor\b", r"\bwhile\b", r"\bcatch\b", r"&&", r"\|\|", r"\?.*:"],
    "typescript": [r"\bif\b", r"\belse if\b", r"\bfor\b", r"\bwhile\b", r"\bcatch\b", r"&&", r"\|\|"],
    "java": [r"\bif\b", r"\belse if\b", r"\bfor\b", r"\bwhile\b", r"\bcatch\b", r"&&", r"\|\|"],
    "php": [r"\bif\b", r"\belseif\b", r"\bfor\b", r"\bforeach\b", r"\bwhile\b", r"\bcatch\b"],
    "go": [r"\bif\b", r"\bfor\b", r"\bswitch\b", r"\bcase\b", r"&&", r"\|\|"],
}


class ComplexityScanner:
    name = "complexity-scanner"

    def __init__(self, progress_cb: Optional[Callable] = None):
        self.progress_cb = progress_cb

    def _report(self, msg: str, prog: float):
        if self.progress_cb:
            try:
                self.progress_cb(msg, prog)
            except Exception:
                pass
        logger.info(f"[{self.name}] {msg}")

    async def scan(self, source: Path) -> list[CodeMetric]:
        self._report("Calculando métricas", 0)
        files = walk_sources(source)
        metrics: list[CodeMetric] = []

        for idx, fpath in enumerate(files):
            if idx % 20 == 0:
                self._report(f"Analizando {idx}/{len(files)}", (idx / max(len(files), 1)) * 100)

            lang = detect_language(fpath)
            if not lang:
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            loc = sum(1 for line in content.splitlines() if line.strip() and not line.strip().startswith(("#", "//", "*", "/*")))
            complexity = self._cyclomatic(content, lang)

            try:
                rel = str(fpath.relative_to(source))
            except ValueError:
                rel = str(fpath)

            metrics.append(CodeMetric(
                file_path=rel,
                language=lang,
                lines_of_code=loc,
                complexity=complexity,
            ))

        self._report(f"Métricas calculadas: {len(metrics)} archivos", 100)
        return metrics

    @staticmethod
    def _cyclomatic(content: str, language: str) -> float:
        """Aproximación CC: 1 + cantidad de branching tokens."""
        tokens = COMPLEXITY_TOKENS.get(language, [])
        count = 1
        for pattern in tokens:
            count += len(re.findall(pattern, content))
        # Normalizar por longitud
        lines = max(1, content.count("\n"))
        return round(count / lines * 10, 2)
