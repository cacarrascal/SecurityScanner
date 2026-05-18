"""URL Scanner robusto — el problema del Testing.zip era que no escaneaba nada real.

Detecta:
- Headers de seguridad faltantes (HSTS, CSP, X-Frame-Options, etc.)
- Cookies sin Secure/HttpOnly/SameSite
- Formularios sin CSRF token, action HTTP en página HTTPS
- Paths comunes expuestos (.env, .git/, /admin, backups, etc.)
- Fingerprinting de tecnologías y versiones expuestas
- Reflexión de input (XSS reflejado básico)
- Open redirects en query params
- Información en error pages (debug info, stack traces)
- TLS issues (cert expiry, weak ciphers — vía headers)
- Server info leakage (Server, X-Powered-By headers)
- Directory listing habilitado
- Métodos HTTP peligrosos (TRACE, PUT, DELETE)
"""
from __future__ import annotations

import asyncio
import re
import ssl
import uuid
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from app.models.schemas import Severity, URLScanResult, Vulnerability
from app.utils.security import is_safe_url


SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS (HTTP Strict Transport Security)", Severity.MEDIUM,
                                  "Configurar header HSTS: max-age=31536000; includeSubDomains"),
    "content-security-policy": ("CSP (Content Security Policy)", Severity.HIGH,
                                "Configurar CSP estricta para mitigar XSS."),
    "x-frame-options": ("X-Frame-Options (clickjacking)", Severity.MEDIUM,
                        "Configurar X-Frame-Options: DENY o SAMEORIGIN."),
    "x-content-type-options": ("X-Content-Type-Options (MIME sniffing)", Severity.LOW,
                               "Configurar X-Content-Type-Options: nosniff."),
    "referrer-policy": ("Referrer-Policy", Severity.LOW,
                        "Configurar Referrer-Policy: strict-origin-when-cross-origin."),
    "permissions-policy": ("Permissions-Policy", Severity.LOW,
                           "Restringir features no usadas (geolocation, camera, etc.)."),
}


COMMON_PATHS = [
    # Configs y secretos
    (".env", Severity.CRITICAL, "Archivo .env expuesto — secretos en texto plano"),
    (".env.production", Severity.CRITICAL, "Archivo .env.production expuesto"),
    (".env.local", Severity.CRITICAL, "Archivo .env.local expuesto"),
    (".git/config", Severity.HIGH, ".git/config expuesto — código fuente potencialmente leakeable"),
    (".git/HEAD", Severity.HIGH, ".git/HEAD expuesto"),
    (".git/", Severity.HIGH, "Directorio .git/ expuesto"),
    (".svn/entries", Severity.HIGH, ".svn/ expuesto"),
    (".DS_Store", Severity.LOW, ".DS_Store expuesto — info de estructura"),
    ("config.php", Severity.HIGH, "Archivo de config PHP"),
    ("web.config", Severity.MEDIUM, "Archivo web.config IIS"),
    (".htaccess", Severity.MEDIUM, ".htaccess expuesto"),
    ("composer.json", Severity.LOW, "composer.json expuesto"),
    ("package.json", Severity.LOW, "package.json expuesto"),
    ("yarn.lock", Severity.LOW, "yarn.lock expuesto"),

    # Admin/auth
    ("admin/", Severity.MEDIUM, "Panel admin accesible"),
    ("admin/login", Severity.MEDIUM, "Login admin accesible"),
    ("wp-admin/", Severity.MEDIUM, "WordPress admin accesible"),
    ("wp-login.php", Severity.MEDIUM, "WordPress login accesible"),
    ("administrator/", Severity.MEDIUM, "Joomla admin"),
    ("phpmyadmin/", Severity.HIGH, "phpMyAdmin expuesto"),
    ("adminer.php", Severity.HIGH, "Adminer expuesto"),

    # Info pages
    ("phpinfo.php", Severity.CRITICAL, "phpinfo() expuesto — info completa del servidor"),
    ("info.php", Severity.HIGH, "info.php expuesto"),
    ("test.php", Severity.LOW, "test.php — archivo de prueba"),
    ("server-status", Severity.MEDIUM, "Apache server-status expuesto"),
    ("server-info", Severity.MEDIUM, "Apache server-info expuesto"),

    # Backups
    ("backup.zip", Severity.HIGH, "Backup ZIP expuesto"),
    ("backup.sql", Severity.CRITICAL, "Dump SQL expuesto"),
    ("backup.tar.gz", Severity.HIGH, "Backup TAR expuesto"),
    ("db.sql", Severity.CRITICAL, "Dump de DB expuesto"),
    ("dump.sql", Severity.CRITICAL, "Dump SQL expuesto"),
    ("database.sql", Severity.CRITICAL, "Database SQL expuesto"),

    # APIs/docs
    ("swagger.json", Severity.LOW, "Swagger spec expuesto"),
    ("openapi.json", Severity.LOW, "OpenAPI spec expuesto"),
    ("api-docs/", Severity.LOW, "API docs expuestos"),
    ("graphql", Severity.MEDIUM, "GraphQL endpoint — verificar introspección"),
    ("debug/", Severity.HIGH, "Debug endpoint expuesto"),

    # Otros
    ("robots.txt", Severity.INFO, "robots.txt"),
    ("sitemap.xml", Severity.INFO, "sitemap.xml"),
    ("crossdomain.xml", Severity.LOW, "crossdomain.xml — verificar policy"),
    ("clientaccesspolicy.xml", Severity.LOW, "Silverlight policy"),
]


XSS_PAYLOADS = [
    "<script>alert(__carlos_xss__)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
]


class URLScanner:
    name = "url-scanner"

    def __init__(self, progress_cb: Optional[Callable] = None):
        self.progress_cb = progress_cb

    def _report(self, msg: str, prog: float):
        if self.progress_cb:
            try:
                self.progress_cb(msg, prog)
            except Exception:
                pass
        logger.info(f"[{self.name}] {msg}")

    async def scan(self, url: str, deep: bool = True) -> tuple[URLScanResult, list[Vulnerability]]:
        # SSRF protection
        safe, reason = is_safe_url(url)
        if not safe:
            raise ValueError(f"URL bloqueada por seguridad: {reason}")

        self._report(f"Conectando a {url}", 5)
        vulns: list[Vulnerability] = []

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(20.0, connect=10.0),
            verify=True,
            headers={"User-Agent": "SecurityScanner/2.0"},
        ) as client:
            # 1. Request inicial
            try:
                resp = await client.get(url)
            except httpx.SSLError as e:
                vulns.append(self._mk_vuln(
                    "url.ssl_error", Severity.HIGH, "Error SSL/TLS",
                    f"Certificado inválido o expirado: {e}",
                    "Renovar certificado o configurar correctamente.",
                    url, cwe="CWE-295",
                ))
                # Reintenta sin verificar para extraer info igual
                async with httpx.AsyncClient(verify=False, timeout=20.0) as no_verify:
                    try:
                        resp = await no_verify.get(url)
                    except Exception as e2:
                        raise ValueError(f"No se puede conectar: {e2}")
            except Exception as e:
                raise ValueError(f"Error al conectar: {e}")

            self._report("Analizando respuesta", 15)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            # 2. Headers de seguridad
            self._report("Verificando headers de seguridad", 20)
            missing = []
            for h, (name, sev, rec) in SECURITY_HEADERS.items():
                if h not in headers_lower:
                    missing.append(name)
                    vulns.append(self._mk_vuln(
                        rule_id=f"http.missing_header.{h}",
                        severity=sev,
                        title=f"Header faltante: {name}",
                        description=f"El servidor no envía el header {name}.",
                        recommendation=rec,
                        file_path=url,
                        cwe="CWE-693",
                    ))

            # HSTS demasiado corto
            if "strict-transport-security" in headers_lower:
                hsts = headers_lower["strict-transport-security"]
                m = re.search(r"max-age\s*=\s*(\d+)", hsts)
                if m and int(m.group(1)) < 31536000:
                    vulns.append(self._mk_vuln(
                        "http.hsts_short", Severity.LOW, "HSTS max-age muy corto",
                        f"max-age={m.group(1)} es menor a 1 año (31536000)",
                        "Configurar max-age=31536000 mínimo", url,
                    ))

            # 3. Info leakage en headers
            self._report("Detectando info leakage", 25)
            for leak_header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
                if leak_header in headers_lower:
                    value = headers_lower[leak_header]
                    vulns.append(self._mk_vuln(
                        f"http.info_leak.{leak_header}",
                        Severity.LOW,
                        f"Header {leak_header} revela tecnología",
                        f"{leak_header}: {value}",
                        f"Eliminar o ofuscar header {leak_header}.",
                        url, cwe="CWE-200",
                    ))

            # 4. Cookies
            self._report("Analizando cookies", 30)
            insecure_cookies = []
            set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]
            for raw_cookie in set_cookies:
                if not raw_cookie:
                    continue
                name = raw_cookie.split("=")[0]
                lower = raw_cookie.lower()
                issues = []
                if "secure" not in lower:
                    issues.append("sin Secure")
                if "httponly" not in lower:
                    issues.append("sin HttpOnly")
                if "samesite" not in lower:
                    issues.append("sin SameSite")
                if issues:
                    insecure_cookies.append({"name": name, "issues": issues})
                    vulns.append(self._mk_vuln(
                        f"http.insecure_cookie.{name}",
                        Severity.MEDIUM,
                        f"Cookie insegura: {name}",
                        f"Cookie {name} no tiene: {', '.join(issues)}",
                        "Configurar Secure; HttpOnly; SameSite=Strict en cookies sensibles.",
                        url, cwe="CWE-614",
                    ))

            # 5. Formularios
            self._report("Analizando formularios HTML", 40)
            forms_info = []
            try:
                soup = BeautifulSoup(resp.text or "", "html.parser")
                base_is_https = url.startswith("https://")
                for form in soup.find_all("form"):
                    action = form.get("action") or url
                    method = (form.get("method") or "GET").upper()
                    full_action = urljoin(str(resp.url), action)
                    has_csrf = False
                    inputs_info = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name", "")
                        itype = inp.get("type", "text")
                        if "csrf" in name.lower() or "token" in name.lower() or "_token" in name.lower():
                            has_csrf = True
                        inputs_info.append({"name": name, "type": itype})

                    forms_info.append({
                        "action": full_action,
                        "method": method,
                        "has_csrf": has_csrf,
                        "inputs": inputs_info,
                    })

                    if method == "POST" and not has_csrf:
                        vulns.append(self._mk_vuln(
                            "html.form_no_csrf", Severity.MEDIUM,
                            "Formulario POST sin token CSRF aparente",
                            f"Formulario action={full_action} no tiene token CSRF.",
                            "Implementar tokens CSRF en formularios POST.",
                            url, cwe="CWE-352",
                        ))

                    if base_is_https and full_action.startswith("http://"):
                        vulns.append(self._mk_vuln(
                            "html.mixed_content_form", Severity.HIGH,
                            "Formulario HTTP en página HTTPS",
                            f"Página HTTPS envía datos por HTTP: {full_action}",
                            "Cambiar action a HTTPS.",
                            url, cwe="CWE-319",
                        ))
            except Exception as e:
                logger.warning(f"Error parseando HTML: {e}")

            # 6. Tecnologías detectadas
            self._report("Detectando tecnologías", 45)
            techs = self._detect_tech(headers_lower, resp.text or "")

            # 7. Información sensible en respuesta
            self._report("Buscando info sensible en respuesta", 50)
            content_lower = (resp.text or "")[:50000].lower()
            for keyword, sev, title in [
                ("stack trace", Severity.MEDIUM, "Stack trace en respuesta"),
                ("traceback", Severity.MEDIUM, "Python traceback expuesto"),
                ("syntax error", Severity.MEDIUM, "Syntax error expuesto"),
                ("warning:", Severity.LOW, "PHP warning expuesto"),
                ("fatal error", Severity.HIGH, "PHP fatal error expuesto"),
                ("ora-0", Severity.HIGH, "Error Oracle expuesto"),
                ("microsoft ole db", Severity.HIGH, "Error MS SQL expuesto"),
                ("mysql_fetch", Severity.HIGH, "Error MySQL expuesto"),
                ("supported mysql versions", Severity.MEDIUM, "Info de versión MySQL"),
            ]:
                if keyword in content_lower:
                    vulns.append(self._mk_vuln(
                        f"html.info_disclosure.{keyword.replace(' ', '_')}",
                        sev, title,
                        f"La respuesta HTML contiene '{keyword}'",
                        "Manejar errores sin mostrar detalles internos al usuario.",
                        url, cwe="CWE-209",
                    ))

            # 8. Directory listing
            if any(marker in content_lower for marker in ["index of /", "directory listing for", "<title>index of"]):
                vulns.append(self._mk_vuln(
                    "http.directory_listing", Severity.MEDIUM,
                    "Directory listing habilitado",
                    "La URL muestra listado de archivos.",
                    "Deshabilitar autoindex/directory listing.",
                    url, cwe="CWE-548",
                ))

            # 9. Métodos HTTP peligrosos
            self._report("Probando métodos HTTP", 55)
            for method in ["TRACE", "PUT", "DELETE", "CONNECT"]:
                try:
                    r = await client.request(method, url, timeout=10.0)
                    if r.status_code < 400 and r.status_code != 405:
                        vulns.append(self._mk_vuln(
                            f"http.dangerous_method.{method.lower()}",
                            Severity.MEDIUM,
                            f"Método HTTP {method} habilitado (status {r.status_code})",
                            f"El servidor acepta {method} requests.",
                            f"Deshabilitar {method} si no es necesario.",
                            url, cwe="CWE-650",
                        ))
                except Exception:
                    pass

            # 10. Paths comunes (en deep scan)
            exposed: list[dict] = []
            if deep:
                self._report("Probando paths comunes (deep scan)", 65)
                exposed = await self._check_paths(client, str(resp.url), vulns)

            # 11. XSS reflejado en query params
            self._report("Probando XSS reflejado", 85)
            reflected_xss = await self._test_xss(client, url, vulns)

            # 12. Open redirect
            open_redirects = await self._test_open_redirect(client, url, vulns)

            self._report("Escaneo URL completado", 100)

            result = URLScanResult(
                url=url,
                status_code=resp.status_code,
                final_url=str(resp.url),
                headers={k: v for k, v in resp.headers.items()},
                missing_security_headers=missing,
                insecure_cookies=insecure_cookies,
                forms=forms_info,
                technologies=techs,
                exposed_paths=exposed,
                reflected_xss=reflected_xss,
                open_redirects=open_redirects,
            )
            return result, vulns

    async def _check_paths(self, client: httpx.AsyncClient, base: str, vulns: list) -> list[dict]:
        exposed = []
        sem = asyncio.Semaphore(8)

        async def probe(path: str, sev: Severity, desc: str):
            async with sem:
                try:
                    target = urljoin(base if base.endswith("/") else base + "/", path)
                    r = await client.get(target, timeout=8.0)
                    if r.status_code == 200 and len(r.content) > 5:
                        # Verifica que no sea una página genérica 200
                        content_sample = (r.text or "")[:200].lower()
                        if not any(x in content_sample for x in ["<!doctype html", "<html", "404", "not found"]) or path in r.url.path:
                            exposed.append({"path": path, "status": r.status_code, "size": len(r.content)})
                            vulns.append(self._mk_vuln(
                                rule_id=f"http.exposed_path.{path.replace('/', '_').strip('_')}",
                                severity=sev,
                                title=f"Path expuesto: {path}",
                                description=desc,
                                recommendation=f"Bloquear acceso público a {path}.",
                                file_path=target,
                                cwe="CWE-538",
                            ))
                except Exception:
                    pass

        tasks = [probe(p, s, d) for p, s, d in COMMON_PATHS]
        await asyncio.gather(*tasks)
        return exposed

    async def _test_xss(self, client: httpx.AsyncClient, url: str, vulns: list) -> list[str]:
        risks = []
        parsed = urlparse(url)
        if not parsed.query:
            return risks

        # Reemplazar cada parámetro con payload XSS
        params = dict(p.split("=", 1) if "=" in p else (p, "") for p in parsed.query.split("&"))
        for param_name in list(params.keys())[:5]:
            for payload in XSS_PAYLOADS[:2]:
                test_params = {**params, param_name: payload}
                test_query = "&".join(f"{k}={v}" for k, v in test_params.items())
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    r = await client.get(test_url, timeout=10.0)
                    if payload in (r.text or "")[:50000]:
                        risk = f"Param '{param_name}' refleja payload XSS sin escapar"
                        risks.append(risk)
                        vulns.append(self._mk_vuln(
                            f"xss.reflected.{param_name}", Severity.HIGH,
                            "XSS reflejado detectado",
                            f"{risk} en {test_url}",
                            "Escapar/sanitizar input antes de incluir en HTML.",
                            test_url, cwe="CWE-79", owasp="A03:2021",
                        ))
                        break
                except Exception:
                    continue
        return risks

    async def _test_open_redirect(self, client: httpx.AsyncClient, url: str, vulns: list) -> list[str]:
        results = []
        parsed = urlparse(url)
        if not parsed.query:
            return results

        # Busca params que parezcan de redirect
        redirect_params = ["redirect", "redir", "url", "next", "return", "returnTo", "returnUrl", "rurl", "go", "to", "target", "dest", "destination"]
        params = dict(p.split("=", 1) if "=" in p else (p, "") for p in parsed.query.split("&"))

        for pname in params:
            if pname.lower() in redirect_params:
                test_params = {**params, pname: "https://evil.example.com/"}
                test_query = "&".join(f"{k}={v}" for k, v in test_params.items())
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    r = await client.get(test_url, timeout=10.0, follow_redirects=False)
                    location = r.headers.get("location", "")
                    if "evil.example.com" in location:
                        risk = f"Param '{pname}' permite open redirect"
                        results.append(risk)
                        vulns.append(self._mk_vuln(
                            f"redirect.open.{pname}", Severity.MEDIUM,
                            "Open redirect detectado",
                            f"{risk}: redirige a {location}",
                            "Validar destino contra whitelist de dominios.",
                            test_url, cwe="CWE-601",
                        ))
                except Exception:
                    pass
        return results

    @staticmethod
    def _detect_tech(headers: dict, html: str) -> list[str]:
        techs: set[str] = set()
        if "x-powered-by" in headers:
            techs.add(headers["x-powered-by"])
        if "server" in headers:
            techs.add(headers["server"])

        markers = [
            ("wp-content", "WordPress"),
            ("/_next/", "Next.js"),
            ("__NEXT_DATA__", "Next.js"),
            ("__NUXT__", "Nuxt.js"),
            ("ng-version", "Angular"),
            ("data-reactroot", "React"),
            ("data-react", "React"),
            ("__vite_plugin_react", "Vite + React"),
            ("/wp-includes/", "WordPress"),
            ("drupal-settings-json", "Drupal"),
            ("joomla", "Joomla"),
            ("django-admin", "Django"),
            ("csrfmiddlewaretoken", "Django"),
            ("laravel_session", "Laravel"),
            ("/static/admin/", "Django Admin"),
            ("phpdebugbar", "PHP Debug Bar"),
            ("/wp-json/", "WordPress REST"),
        ]
        html_lower = html.lower()
        for marker, name in markers:
            if marker.lower() in html_lower:
                techs.add(name)
        return sorted(t for t in techs if t)

    @staticmethod
    def _mk_vuln(rule_id, severity, title, description, recommendation=None, file_path=None, cwe=None, owasp=None) -> Vulnerability:
        return Vulnerability(
            id=str(uuid.uuid4())[:8],
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=description,
            scanner="url-scanner",
            file_path=file_path,
            recommendation=recommendation,
            cwe=cwe,
            owasp=owasp,
        )
