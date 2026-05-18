"""Orquestador del pipeline de scan, adaptado a serverless (Vercel).

Cambios vs. versión original:
- Ya NO usa asyncio.create_task: la pipeline corre dentro de la request HTTP
  (Vercel mata cualquier tarea de background al enviar la respuesta).
- Ya NO mantiene `_results` global: el resultado se devuelve directamente y se
  emite por SSE; el cliente lo guarda en localStorage.
- Reemplaza ws_manager por EventStream (SSE).
- Quita Semgrep (no cabe en 250 MB de Vercel). Bandit sigue siendo opcional.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Optional

from loguru import logger

from app.models.schemas import (
    DependencyIssue, ScanResult, ScanStatus, ScanType, Severity, Vulnerability,
)
from app.scanners import BanditScanner, ComplexityScanner, DependencyScanner, PatternScanner
from app.services.events import EventStream
from app.services.url_scanner import URLScanner
from app.utils.workspace import Workspace


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _cb_factory(events: EventStream, name: str, base: float, weight: float):
    def cb(msg: str, prog: float) -> None:
        overall = base + (prog / 100.0) * weight
        events.progress(name, overall, msg)
    return cb


async def run_project_scan(
    events: EventStream,
    ws: Workspace,
    scan_id: str,
    target: str,
    scan_type: ScanType,
) -> ScanResult:
    """Pipeline completo de análisis de proyecto, síncrono dentro del request."""
    result = ScanResult(
        scan_id=scan_id,
        scan_type=scan_type,
        status=ScanStatus.RUNNING,
        target=target,
        started_at=datetime.utcnow(),
    )

    try:
        events.status("running", "Iniciando análisis del proyecto")
        events.log(f"Workspace: {ws.id}")
        events.progress("init", 0, "Pipeline iniciado")

        all_vulns: list[Vulnerability] = []
        all_deps: list[DependencyIssue] = []

        # 1. Pattern (0-40%) — embebido, siempre corre
        events.log("▶ Pattern scanner (embebido)")
        pattern = PatternScanner(progress_cb=_cb_factory(events, "pattern", 0, 40))
        pattern_vulns = await pattern.scan(ws.source)
        all_vulns.extend(pattern_vulns)
        events.log(f"✓ Pattern: {len(pattern_vulns)} hallazgos", "success")

        # 2. Dependency (40-60%)
        events.log("▶ Dependency scanner")
        dep = DependencyScanner(progress_cb=_cb_factory(events, "dependency", 40, 20))
        deps = await dep.scan(ws.source)
        all_deps.extend(deps)
        events.log(f"✓ Dependencies: {len(deps)} vulnerables", "success")

        # 3. Complexity (60-80%)
        events.log("▶ Complexity scanner")
        comp = ComplexityScanner(progress_cb=_cb_factory(events, "complexity", 60, 20))
        metrics = await comp.scan(ws.source)
        result.code_metrics = metrics
        events.log(f"✓ Métricas: {len(metrics)} archivos", "success")

        # 4. Bandit (80-95%) — opcional, solo si el binario está disponible
        events.log("▶ Bandit (opcional)")
        bandit = BanditScanner(progress_cb=_cb_factory(events, "bandit", 80, 15))
        if bandit.available():
            bandit_vulns = await bandit.scan(ws.source)
            all_vulns.extend(bandit_vulns)
            events.log(f"✓ Bandit: {len(bandit_vulns)} hallazgos", "success")
        else:
            events.log("⚠ Bandit no instalado — saltado", "warning")

        # 5. Scoring + métricas
        events.progress("finalize", 95, "Calculando scoring")
        result.vulnerabilities = all_vulns
        result.dependencies = all_deps
        result.security_score = _calc_security_score(all_vulns, all_deps)
        result.quality_score = _calc_quality_score(metrics)
        result.metrics = _build_metrics(all_vulns, all_deps, metrics)

        result.status = ScanStatus.COMPLETED
        result.completed_at = datetime.utcnow()
        events.progress("done", 100, "Análisis completado")
        events.status("completed", "Listo")
        events.log(
            f"Análisis completado: {len(all_vulns)} vulns, {len(all_deps)} deps vulnerables, "
            f"score {result.security_score}/100",
            "success",
        )
    except Exception as e:
        logger.exception(f"Error en pipeline {scan_id}")
        result.status = ScanStatus.FAILED
        result.error = str(e)
        result.completed_at = datetime.utcnow()
        events.status("failed", str(e))
        events.log(f"✗ Error: {e}", "error")

    return result


async def run_url_scan(
    events: EventStream,
    scan_id: str,
    url: str,
    deep: bool = True,
) -> ScanResult:
    """Pipeline de escaneo de URL, síncrono dentro del request."""
    result = ScanResult(
        scan_id=scan_id,
        scan_type=ScanType.URL,
        status=ScanStatus.RUNNING,
        target=url,
        started_at=datetime.utcnow(),
    )

    try:
        events.status("running", f"Escaneando {url}")
        events.progress("init", 0, "Pipeline iniciado")

        def cb(msg: str, prog: float) -> None:
            events.progress("url-scan", prog, msg)

        scanner = URLScanner(progress_cb=cb)
        url_result, url_vulns = await scanner.scan(url, deep=deep)

        result.url_result = url_result
        result.vulnerabilities = url_vulns
        result.security_score = _calc_security_score(url_vulns, [])
        result.metrics = _build_metrics(url_vulns, [], [])
        result.metrics["url_status_code"] = url_result.status_code
        result.metrics["forms_detected"] = len(url_result.forms)
        result.metrics["paths_exposed"] = len(url_result.exposed_paths)
        result.metrics["technologies"] = url_result.technologies

        result.status = ScanStatus.COMPLETED
        result.completed_at = datetime.utcnow()
        events.progress("done", 100, "Escaneo completado")
        events.status("completed", "Listo")
        events.log(
            f"URL scan completado: {len(url_vulns)} vulns, score {result.security_score}/100",
            "success",
        )
    except Exception as e:
        logger.exception(f"Error en URL pipeline {scan_id}")
        result.status = ScanStatus.FAILED
        result.error = str(e)
        result.completed_at = datetime.utcnow()
        events.status("failed", str(e))
        events.log(f"✗ Error: {e}", "error")

    return result


def _calc_security_score(vulns: list, deps: list) -> float:
    penalty = 0.0
    for v in vulns:
        penalty += SEVERITY_WEIGHTS.get(v.severity, 0)
    for d in deps:
        penalty += SEVERITY_WEIGHTS.get(d.severity, 0) * 1.5
    return max(0.0, round(100.0 - penalty, 1))


def _calc_quality_score(metrics: list) -> float:
    if not metrics:
        return 100.0
    avg_complexity = sum(m.complexity for m in metrics) / len(metrics)
    penalty = min(50.0, max(0.0, (avg_complexity - 5) * 5))
    return max(0.0, round(100.0 - penalty, 1))


def _build_metrics(vulns: list, deps: list, code_metrics: list) -> dict:
    sev_count = {s.value: 0 for s in Severity}
    for v in vulns:
        sev_count[v.severity.value] += 1
    for d in deps:
        sev_count[d.severity.value] += 1

    total_loc = sum(m.lines_of_code for m in code_metrics)
    languages: dict[str, int] = {}
    for m in code_metrics:
        languages[m.language] = languages.get(m.language, 0) + 1

    files_affected = len({v.file_path for v in vulns if v.file_path})

    return {
        "total_vulnerabilities": len(vulns),
        "total_dependency_issues": len(deps),
        "severity_breakdown": sev_count,
        "files_affected": files_affected,
        "total_files": len(code_metrics),
        "lines_of_code": total_loc,
        "languages": languages,
    }
