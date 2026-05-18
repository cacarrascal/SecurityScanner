"""Generador de reportes HTML, PDF, JSON. PDF via ReportLab (sin deps de sistema)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from loguru import logger

from app.models.schemas import ScanResult


HTML_TPL = """<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<title>SecurityScanner Report — {scan_id}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#c9d1d9;padding:32px;line-height:1.6}}
.c{{max-width:1100px;margin:0 auto}}
header{{border-bottom:1px solid #30363d;padding-bottom:20px;margin-bottom:24px}}
h1{{color:#58a6ff;font-size:28px}}
h2{{color:#f0f6fc;font-size:20px;margin:24px 0 12px;border-bottom:1px solid #30363d;padding-bottom:6px}}
.meta{{color:#8b949e;font-size:13px}}
.scores{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:20px 0}}
.score{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center}}
.score-val{{font-size:48px;font-weight:700}}
.score-lbl{{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:1px}}
.good{{color:#3fb950}}.warn{{color:#d29922}}.bad{{color:#f85149}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;text-align:center}}
.stat-n{{font-size:24px;font-weight:700;color:#f0f6fc}}
.stat-l{{color:#8b949e;font-size:11px;text-transform:uppercase}}
.vuln{{background:#161b22;border-left:4px solid #30363d;border-radius:4px;padding:12px;margin:8px 0}}
.vuln.critical{{border-left-color:#f85149}}
.vuln.high{{border-left-color:#ff7b72}}
.vuln.medium{{border-left-color:#d29922}}
.vuln.low{{border-left-color:#58a6ff}}
.vuln.info{{border-left-color:#8b949e}}
.vuln-t{{font-weight:600;color:#f0f6fc}}
.vuln-m{{font-size:12px;color:#8b949e;margin-top:4px}}
.vuln-d{{margin-top:6px;font-size:14px}}
code,pre{{font-family:SF Mono,Monaco,monospace;font-size:12px}}
code{{background:#0d1117;padding:2px 6px;border-radius:3px}}
pre{{background:#0d1117;padding:10px;border-radius:6px;overflow-x:auto;margin-top:8px}}
.badge{{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:700;text-transform:uppercase}}
.b-critical{{background:#f85149;color:#fff}}
.b-high{{background:#ff7b72;color:#fff}}
.b-medium{{background:#d29922;color:#161b22}}
.b-low{{background:#58a6ff;color:#fff}}
.b-info{{background:#8b949e;color:#fff}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
th,td{{padding:10px;text-align:left;border-bottom:1px solid #30363d;font-size:14px}}
th{{color:#8b949e;font-size:12px;text-transform:uppercase}}
footer{{margin-top:40px;padding-top:20px;border-top:1px solid #30363d;color:#8b949e;font-size:12px;text-align:center}}
</style></head><body><div class="c">
<header><h1>🛡 SecurityScanner Report</h1><div class="meta">
<div>Scan ID: <code>{scan_id}</code></div>
<div>Target: <code>{target}</code></div>
<div>Tipo: <code>{scan_type}</code></div>
<div>Iniciado: {started_at} · Completado: {completed_at}</div>
</div></header>

<div class="scores">
<div class="score"><div class="score-val {sec_class}">{security_score}</div><div class="score-lbl">Security Score</div></div>
<div class="score"><div class="score-val {qual_class}">{quality_score}</div><div class="score-lbl">Quality Score</div></div>
</div>

<h2>Resumen</h2>
<div class="stats">
<div class="stat"><div class="stat-n">{total_vulns}</div><div class="stat-l">Vulnerabilidades</div></div>
<div class="stat"><div class="stat-n">{total_deps}</div><div class="stat-l">Deps vulnerables</div></div>
<div class="stat"><div class="stat-n">{files_affected}</div><div class="stat-l">Archivos afectados</div></div>
<div class="stat"><div class="stat-n">{total_loc}</div><div class="stat-l">Líneas de código</div></div>
</div>

<h2>Severidad</h2>
<table><tr><th>Crítica</th><th>Alta</th><th>Media</th><th>Baja</th><th>Info</th></tr>
<tr>
<td><span class="badge b-critical">{sev_critical}</span></td>
<td><span class="badge b-high">{sev_high}</span></td>
<td><span class="badge b-medium">{sev_medium}</span></td>
<td><span class="badge b-low">{sev_low}</span></td>
<td><span class="badge b-info">{sev_info}</span></td>
</tr></table>

<h2>Vulnerabilidades ({total_vulns})</h2>
{vulns_html}

<h2>Dependencias vulnerables ({total_deps})</h2>
{deps_html}

<footer>Generado por SecurityScanner · {now}</footer>
</div></body></html>"""


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self, result: ScanResult) -> dict:
        outs = {}
        outs["json"] = self.generate_json(result)
        outs["html"] = self.generate_html(result)
        try:
            outs["pdf"] = self.generate_pdf(result)
        except Exception as e:
            logger.warning(f"PDF no generado: {e}")
        return outs

    def generate_json(self, result: ScanResult) -> Path:
        target = self.output_dir / "report.json"
        target.write_text(result.model_dump_json(indent=2))
        return target

    def generate_html(self, result: ScanResult) -> Path:
        sev = result.metrics.get("severity_breakdown", {})

        vulns_html_list = []
        for v in result.vulnerabilities[:300]:
            extras = []
            if v.cwe:
                extras.append(f"CWE: {v.cwe}")
            if v.owasp:
                extras.append(f"OWASP: {v.owasp}")
            extras_html = " · ".join(extras) if extras else ""
            snippet = f'<pre>{self._escape(v.code_snippet[:400])}</pre>' if v.code_snippet else ""
            rec = f'<div class="vuln-m">💡 {self._escape(v.recommendation)}</div>' if v.recommendation else ""
            vulns_html_list.append(f"""
<div class="vuln {v.severity.value}">
<div><span class="badge b-{v.severity.value}">{v.severity.value}</span> <span class="vuln-t">{self._escape(v.title)}</span></div>
<div class="vuln-m">Rule: <code>{self._escape(v.rule_id)}</code> · Scanner: {v.scanner} · {self._escape(v.file_path or '-')}{f':{v.line_number}' if v.line_number else ''} {f'· {extras_html}' if extras_html else ''}</div>
<div class="vuln-d">{self._escape(v.description)}</div>
{snippet}{rec}
</div>""")

        vulns_html = "".join(vulns_html_list) or '<p style="color:#3fb950">✓ Sin vulnerabilidades detectadas.</p>'

        deps_rows = ""
        for d in result.dependencies[:100]:
            deps_rows += f"<tr><td>{self._escape(d.package)}</td><td>{self._escape(d.version)}</td><td><code>{self._escape(d.vulnerability_id)}</code></td><td><span class='badge b-{d.severity.value}'>{d.severity.value}</span></td><td>{self._escape(d.fix_version or '-')}</td></tr>"
        deps_html = f"<table><tr><th>Paquete</th><th>Versión</th><th>CVE</th><th>Severidad</th><th>Fix</th></tr>{deps_rows}</table>" if deps_rows else "<p>Sin deps vulnerables.</p>"

        html = HTML_TPL.format(
            scan_id=result.scan_id,
            target=self._escape(result.target),
            scan_type=result.scan_type.value,
            started_at=result.started_at.isoformat(),
            completed_at=result.completed_at.isoformat() if result.completed_at else "—",
            security_score=result.security_score,
            quality_score=result.quality_score,
            sec_class=self._score_class(result.security_score),
            qual_class=self._score_class(result.quality_score),
            total_vulns=len(result.vulnerabilities),
            total_deps=len(result.dependencies),
            files_affected=result.metrics.get("files_affected", 0),
            total_loc=result.metrics.get("lines_of_code", 0),
            sev_critical=sev.get("critical", 0),
            sev_high=sev.get("high", 0),
            sev_medium=sev.get("medium", 0),
            sev_low=sev.get("low", 0),
            sev_info=sev.get("info", 0),
            vulns_html=vulns_html,
            deps_html=deps_html,
            now=datetime.utcnow().isoformat(),
        )
        target = self.output_dir / "report.html"
        target.write_text(html, encoding="utf-8")
        return target

    def generate_pdf(self, result: ScanResult) -> Path:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)
        from reportlab.lib.units import inch

        target = self.output_dir / "report.pdf"
        doc = SimpleDocTemplate(str(target), pagesize=letter, topMargin=0.5*inch)
        styles = getSampleStyleSheet()
        title_st = ParagraphStyle("title", parent=styles["Title"], textColor=colors.HexColor("#58a6ff"))
        h2_st = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#1f6feb"))

        story = [
            Paragraph("SecurityScanner Report", title_st),
            Spacer(1, 0.15*inch),
            Paragraph(f"<b>Scan ID:</b> {result.scan_id}", styles["Normal"]),
            Paragraph(f"<b>Target:</b> {self._escape(result.target)}", styles["Normal"]),
            Paragraph(f"<b>Type:</b> {result.scan_type.value}", styles["Normal"]),
            Spacer(1, 0.2*inch),
            Paragraph(f"<b>Security Score:</b> {result.security_score}/100", h2_st),
            Paragraph(f"<b>Quality Score:</b> {result.quality_score}/100", h2_st),
            Spacer(1, 0.2*inch),
        ]

        sev = result.metrics.get("severity_breakdown", {})
        sev_table = Table(
            [["Critical", "High", "Medium", "Low", "Info"],
             [sev.get("critical", 0), sev.get("high", 0), sev.get("medium", 0), sev.get("low", 0), sev.get("info", 0)]],
            colWidths=[1*inch]*5,
        )
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#30363d")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
            ("BACKGROUND", (0,1), (0,1), colors.HexColor("#f85149")),
            ("BACKGROUND", (1,1), (1,1), colors.HexColor("#ff7b72")),
            ("BACKGROUND", (2,1), (2,1), colors.HexColor("#d29922")),
            ("BACKGROUND", (3,1), (3,1), colors.HexColor("#58a6ff")),
            ("BACKGROUND", (4,1), (4,1), colors.HexColor("#8b949e")),
            ("TEXTCOLOR", (0,1), (-1,1), colors.white),
            ("ALIGN", (0,0), (-1,-1), "CENTER"),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,1), (-1,1), 14),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph(f"<b>Vulnerabilidades ({len(result.vulnerabilities)})</b>", h2_st))
        for v in result.vulnerabilities[:60]:
            story.append(Paragraph(
                f"[{v.severity.value.upper()}] <b>{self._escape(v.title)}</b><br/>"
                f"<font size=8 color='#8b949e'>{self._escape(v.file_path or '-')}:{v.line_number or '-'} · {v.scanner}</font><br/>"
                f"<font size=9>{self._escape(v.description[:300])}</font>",
                styles["Normal"]
            ))
            story.append(Spacer(1, 0.05*inch))

        if result.dependencies:
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph(f"<b>Dependencias vulnerables ({len(result.dependencies)})</b>", h2_st))
            for d in result.dependencies[:30]:
                story.append(Paragraph(
                    f"[{d.severity.value.upper()}] <b>{d.package} {d.version}</b> → {d.vulnerability_id}<br/>"
                    f"<font size=9>{self._escape(d.description[:200])}</font>",
                    styles["Normal"]
                ))
                story.append(Spacer(1, 0.05*inch))

        doc.build(story)
        return target

    @staticmethod
    def _escape(s) -> str:
        if not s:
            return ""
        return (str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))

    @staticmethod
    def _score_class(score: float) -> str:
        return "good" if score >= 80 else "warn" if score >= 50 else "bad"
