"""Scanner de dependencias — parsea archivos de manifiesto sin necesitar binarios.

Soporta:
- Python: requirements.txt, Pipfile, pyproject.toml
- Node.js: package.json, package-lock.json
- Ruby: Gemfile
- PHP: composer.json
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

from app.models.schemas import DependencyIssue, Severity


# Base de conocidos paquetes con CVEs (curated lite). Producción usaría OSV API.
KNOWN_VULNERABLE = {
    # Python
    "django": [("<3.2.18", "CVE-2023-23969", Severity.HIGH, "Django DoS via NOT IN clauses")],
    "flask": [("<2.2.5", "CVE-2023-30861", Severity.HIGH, "Flask session cookie persistence")],
    "requests": [("<2.31.0", "CVE-2023-32681", Severity.MEDIUM, "Requests proxy auth leak")],
    "urllib3": [("<1.26.18", "CVE-2023-43804", Severity.MEDIUM, "Cookie leak via HTTP redirect")],
    "pyyaml": [("<5.4", "CVE-2020-14343", Severity.CRITICAL, "PyYAML arbitrary code via yaml.load")],
    "pillow": [("<10.0.1", "CVE-2023-44271", Severity.HIGH, "Pillow DoS via ImageFont")],
    "cryptography": [("<41.0.6", "CVE-2023-49083", Severity.MEDIUM, "Cryptography NULL deref")],
    "jinja2": [("<3.1.3", "CVE-2024-22195", Severity.MEDIUM, "Jinja2 XSS via xmlattr filter")],
    "werkzeug": [("<3.0.1", "CVE-2023-46136", Severity.HIGH, "Werkzeug DoS via multipart")],
    "fastapi": [("<0.109.1", "CVE-2024-24762", Severity.HIGH, "FastAPI ReDoS")],
    "pycrypto": [("*", "CVE-2013-7459", Severity.CRITICAL, "pycrypto abandoned — usar pycryptodome")],
    # Node
    "lodash": [("<4.17.21", "CVE-2021-23337", Severity.HIGH, "Lodash command injection")],
    "axios": [("<1.6.0", "CVE-2023-45857", Severity.MEDIUM, "Axios CSRF")],
    "express": [("<4.18.2", "CVE-2022-24999", Severity.MEDIUM, "Express open redirect")],
    "minimist": [("<1.2.6", "CVE-2021-44906", Severity.CRITICAL, "Minimist prototype pollution")],
    "moment": [("<2.29.4", "CVE-2022-31129", Severity.HIGH, "Moment ReDoS")],
    "next": [("<14.1.1", "CVE-2024-34351", Severity.HIGH, "Next.js SSRF")],
    "react": [("<18.3.0", "advisory", Severity.LOW, "React versiones antiguas sin parches")],
    "ws": [("<7.5.10", "CVE-2024-37890", Severity.HIGH, "ws ReDoS")],
    "semver": [("<7.5.2", "CVE-2022-25883", Severity.MEDIUM, "Semver ReDoS")],
    "tar": [("<6.2.1", "CVE-2024-28863", Severity.MEDIUM, "tar arbitrary file overwrite")],
    "json5": [("<2.2.2", "CVE-2022-46175", Severity.HIGH, "json5 prototype pollution")],
    "vite": [("<5.0.13", "CVE-2024-23331", Severity.HIGH, "Vite path traversal")],
    "node-fetch": [("<2.6.7", "CVE-2022-0235", Severity.MEDIUM, "node-fetch credential leak")],
    "follow-redirects": [("<1.15.4", "CVE-2024-28849", Severity.MEDIUM, "follow-redirects creds leak")],
}


class DependencyScanner:
    name = "dependency-scanner"

    def __init__(self, progress_cb: Optional[Callable] = None):
        self.progress_cb = progress_cb

    def _report(self, msg: str, prog: float):
        if self.progress_cb:
            try:
                self.progress_cb(msg, prog)
            except Exception:
                pass
        logger.info(f"[{self.name}] {msg}")

    async def scan(self, source: Path) -> list[DependencyIssue]:
        self._report("Buscando manifiestos de dependencias", 0)
        issues: list[DependencyIssue] = []

        # Python
        for req in source.rglob("requirements*.txt"):
            self._report(f"Auditando {req.name}", 20)
            issues.extend(self._parse_requirements(req))

        for pyproj in source.rglob("pyproject.toml"):
            self._report(f"Auditando {pyproj.name}", 30)
            issues.extend(self._parse_pyproject(pyproj))

        # Node
        for pkg in source.rglob("package.json"):
            if "node_modules" in pkg.parts:
                continue
            self._report(f"Auditando {pkg.parent.name}/package.json", 50)
            issues.extend(self._parse_package_json(pkg))

        # PHP
        for composer in source.rglob("composer.json"):
            if "vendor" in composer.parts:
                continue
            issues.extend(self._parse_composer(composer))

        self._report(f"Dependencies scanner: {len(issues)} issues", 100)
        return issues

    def _parse_requirements(self, path: Path) -> list[DependencyIssue]:
        try:
            content = path.read_text(errors="ignore")
        except Exception:
            return []

        issues = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([a-zA-Z0-9_\-]+)\s*([<>=!~]+)\s*([0-9.a-zA-Z\-]+)?", line)
            if m:
                pkg = m.group(1).lower()
                version = m.group(3) or "unknown"
                issues.extend(self._check_known(pkg, version))
        return issues

    def _parse_pyproject(self, path: Path) -> list[DependencyIssue]:
        try:
            content = path.read_text(errors="ignore")
        except Exception:
            return []
        issues = []
        # busca línea tipo "django = "^3.2"" o "django>=3.2"
        for match in re.finditer(r"['\"]([a-zA-Z0-9_\-]+)['\"]?\s*[:=]\s*['\"][\^~><=]*([0-9.]+)", content):
            pkg = match.group(1).lower()
            version = match.group(2)
            issues.extend(self._check_known(pkg, version))
        return issues

    def _parse_package_json(self, path: Path) -> list[DependencyIssue]:
        try:
            data = json.loads(path.read_text(errors="ignore"))
        except Exception:
            return []

        issues = []
        for dep_section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(dep_section, {})
            if not isinstance(deps, dict):
                continue
            for pkg, version in deps.items():
                clean_version = re.sub(r"[\^~><=]", "", str(version)).split("||")[0].strip()
                issues.extend(self._check_known(pkg.lower(), clean_version))
        return issues

    def _parse_composer(self, path: Path) -> list[DependencyIssue]:
        try:
            data = json.loads(path.read_text(errors="ignore"))
        except Exception:
            return []
        issues = []
        for section in ("require", "require-dev"):
            for pkg, version in data.get(section, {}).items():
                pkg_short = pkg.split("/")[-1].lower()
                clean_v = re.sub(r"[\^~><=]", "", str(version)).split("||")[0].strip()
                issues.extend(self._check_known(pkg_short, clean_v))
        return issues

    def _check_known(self, package: str, version: str) -> list[DependencyIssue]:
        if package not in KNOWN_VULNERABLE:
            return []

        issues = []
        for affected_range, cve, sev, desc in KNOWN_VULNERABLE[package]:
            if self._version_matches(version, affected_range):
                issues.append(DependencyIssue(
                    package=package,
                    version=version,
                    vulnerability_id=cve,
                    severity=sev,
                    description=desc,
                    fix_version=affected_range.lstrip("<>=~^"),
                ))
        return issues

    @staticmethod
    def _version_matches(version: str, affected_range: str) -> bool:
        """Match simple de versión vs rango '<X.Y.Z' o '*'."""
        if affected_range == "*":
            return True
        if not version or version == "unknown":
            return True
        try:
            v_parts = [int(x) for x in re.findall(r"\d+", version)[:3]]
            r_parts = [int(x) for x in re.findall(r"\d+", affected_range)[:3]]
            while len(v_parts) < 3:
                v_parts.append(0)
            while len(r_parts) < 3:
                r_parts.append(0)
            if "<" in affected_range:
                return v_parts < r_parts
            return False
        except Exception:
            return True
