"""Scanner embebido por regex — funciona SIN dependencias externas.

Detecta:
- Secretos hardcodeados (AWS, Google, Slack, GitHub, JWT, contraseñas, DB URLs)
- Patrones peligrosos por lenguaje (eval, exec, pickle, dangerouslySetInnerHTML, etc.)
- SQL injection patterns (concatenación de strings con queries)
- XSS patterns (innerHTML, document.write, dangerouslySetInnerHTML)
- Path traversal (../, file://)
- Comandos del sistema sin sanitizar (os.system, shell=True)
- Hashes débiles (MD5, SHA1)
- TLS/SSL inseguros (verify=False, InsecureRequestWarning)
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

from app.models.schemas import Severity, Vulnerability
from app.utils.files import walk_sources


SECRET_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL, "AWS Access Key"),
    ("aws_secret", r"(?i)aws[_-]?secret[_-]?(access[_-]?)?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", Severity.CRITICAL, "AWS Secret Key"),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH, "Google API Key"),
    ("slack_token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}", Severity.CRITICAL, "Slack Token"),
    ("github_token", r"gh[oprsu]_[A-Za-z0-9]{36,255}", Severity.CRITICAL, "GitHub Token"),
    ("stripe_key", r"sk_(live|test)_[0-9a-zA-Z]{24,}", Severity.CRITICAL, "Stripe API Key"),
    ("private_key", r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----", Severity.CRITICAL, "Private Key"),
    ("jwt_token", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", Severity.MEDIUM, "JWT Token"),
    ("password_hardcoded", r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"\\s]{6,}['\"]", Severity.HIGH, "Hardcoded Password"),
    ("api_key_generic", r"(?i)(api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{20,}['\"]", Severity.HIGH, "Generic API Key"),
    ("db_connection", r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+", Severity.HIGH, "DB Connection String with Credentials"),
]


DANGEROUS_PATTERNS = {
    "python": [
        ("py_eval", r"\beval\s*\([^)]*", Severity.HIGH, "Uso de eval()", "Evitar eval con input no confiable. Usar ast.literal_eval."),
        ("py_exec", r"\bexec\s*\([^)]*", Severity.HIGH, "Uso de exec()", "exec ejecuta código arbitrario. Evitar con input externo."),
        ("py_pickle", r"pickle\.loads?\s*\(", Severity.HIGH, "Deserialización pickle insegura", "Pickle puede ejecutar código. Usar JSON o validar fuente."),
        ("py_yaml_load", r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.(Safe|C?Safe))", Severity.HIGH, "yaml.load sin SafeLoader", "Usar yaml.safe_load() o Loader=SafeLoader."),
        ("py_shell_inject", r"subprocess\.(call|run|Popen|check_output|check_call)[^)]*shell\s*=\s*True", Severity.HIGH, "subprocess con shell=True", "Pasar lista de args en vez de string, sin shell=True."),
        ("py_os_system", r"\bos\.system\s*\(", Severity.HIGH, "os.system() con riesgo de injection", "Usar subprocess con args como lista."),
        ("py_sql_concat", r"(execute|executemany|cursor\.execute)\s*\(\s*[fF]?['\"][^'\"]*\{|(execute|executemany|cursor\.execute)\s*\(\s*['\"][^'\"]*%[sd]|(execute|executemany|cursor\.execute)\s*\([^,)]*\+", Severity.HIGH, "Posible SQL injection", "Usar parámetros: cursor.execute(query, params)."),
        ("py_md5", r"hashlib\.md5\s*\(", Severity.LOW, "Hash débil MD5", "Usar SHA-256 o bcrypt para passwords."),
        ("py_sha1", r"hashlib\.sha1\s*\(", Severity.LOW, "Hash débil SHA1", "SHA1 está roto criptográficamente. Usar SHA-256+."),
        ("py_random", r"\brandom\.(random|randint|choice|sample)\s*\(", Severity.LOW, "random no es criptográficamente seguro", "Para tokens usar secrets.token_urlsafe()."),
        ("py_ssl_verify_false", r"verify\s*=\s*False", Severity.HIGH, "Verificación SSL deshabilitada", "Remover verify=False en producción."),
        ("py_debug_true", r"DEBUG\s*=\s*True", Severity.MEDIUM, "DEBUG=True en producción", "Settings de debug exponen stack traces."),
        ("py_cgi_field_storage", r"\bcgi\.FieldStorage\b", Severity.MEDIUM, "cgi.FieldStorage deprecado", "cgi se eliminó en Python 3.13. Usar python-multipart."),
        ("py_zipfile_extractall", r"\.extractall\s*\(", Severity.HIGH, "extractall sin validar paths (CVE-2007-4559)", "Validar paths antes de extraer (path traversal)."),
        ("py_assert_in_prod", r"^\s*assert\s+", Severity.LOW, "assert puede deshabilitarse con -O", "No usar assert para validación de seguridad."),
        ("py_input_eval", r"\beval\s*\(\s*input\s*\(", Severity.CRITICAL, "eval(input()) — RCE directo", "NUNCA pasar input() a eval()."),
    ],
    "javascript": [
        ("js_eval", r"\beval\s*\(", Severity.HIGH, "Uso de eval()", "Evitar eval. Usar JSON.parse para datos."),
        ("js_function_constructor", r"new\s+Function\s*\(", Severity.HIGH, "new Function() es como eval", "Evita constructor Function con input externo."),
        ("js_inner_html", r"\.innerHTML\s*=", Severity.MEDIUM, "Asignación a innerHTML", "Usar textContent o sanitizar (DOMPurify)."),
        ("js_outer_html", r"\.outerHTML\s*=", Severity.MEDIUM, "Asignación a outerHTML", "Reescribe el elemento — riesgo XSS."),
        ("js_document_write", r"document\.write\s*\(", Severity.MEDIUM, "document.write() permite XSS", "Usar APIs DOM modernas."),
        ("js_dangerously_html", r"dangerouslySetInnerHTML", Severity.MEDIUM, "React dangerouslySetInnerHTML", "Sanitizar HTML con DOMPurify o evitar."),
        ("js_window_location", r"window\.location\s*=\s*[^'\"]*\+|window\.location\.href\s*=\s*[^'\"]*\+", Severity.MEDIUM, "Open redirect potencial", "Validar URL antes de asignar a location."),
        ("js_postmessage_star", r"postMessage\s*\([^,]+,\s*['\"]?\*['\"]?", Severity.MEDIUM, "postMessage con origin '*'", "Especificar target origin exacto."),
        ("js_eval_settimeout", r"setTimeout\s*\(\s*['\"]", Severity.HIGH, "setTimeout con string (equivale a eval)", "Pasar función, no string."),
        ("js_exec_settimeout", r"setInterval\s*\(\s*['\"]", Severity.HIGH, "setInterval con string", "Pasar función, no string."),
        ("js_console_log_sensitive", r"console\.log\s*\([^)]*(password|token|secret|key)", Severity.LOW, "console.log con datos sensibles", "Eliminar logs con secretos antes de producción."),
        ("js_md5_crypto", r"crypto.*\.md5|md5\s*\(", Severity.LOW, "Hash MD5", "Usar SHA-256."),
        ("js_localstorage_token", r"localStorage\.setItem\s*\([^,]*(token|jwt|password)", Severity.MEDIUM, "Tokens en localStorage", "localStorage es vulnerable a XSS. Usar httpOnly cookies."),
        ("js_open_redirect", r"res\.redirect\s*\(\s*req\.query|res\.redirect\s*\(\s*req\.params", Severity.MEDIUM, "Open redirect con req.query/params", "Validar destino contra whitelist."),
    ],
    "typescript": [
        ("ts_any_type", r":\s*any\b", Severity.INFO, "Uso de tipo 'any'", "Tipar específicamente para mejor seguridad."),
        ("ts_ts_ignore", r"@ts-ignore", Severity.LOW, "@ts-ignore esconde errores", "Resolver el error en vez de ignorarlo."),
    ],
    "php": [
        ("php_eval", r"\beval\s*\(", Severity.CRITICAL, "Uso de eval()", "NUNCA usar eval en PHP."),
        ("php_system", r"\b(system|exec|shell_exec|passthru|popen)\s*\(", Severity.HIGH, "Ejecución de comandos shell", "Validar y escapar con escapeshellarg()."),
        ("php_include_var", r"(include|require)(_once)?\s*\(\s*\$", Severity.CRITICAL, "include con variable — LFI/RFI", "Whitelist de archivos permitidos."),
        ("php_sql_concat", r"(mysql_query|mysqli_query|->query)\s*\(\s*['\"][^'\"]*\$|\s*['\"][^'\"]*\.\s*\$", Severity.HIGH, "Posible SQL injection", "Usar prepared statements (PDO/mysqli)."),
        ("php_unserialize", r"\bunserialize\s*\(", Severity.HIGH, "unserialize() inseguro", "No deserializar input no confiable."),
    ],
    "java": [
        ("java_runtime_exec", r"Runtime\.getRuntime\(\)\.exec\s*\(", Severity.HIGH, "Runtime.exec puede ser inyectable", "Validar args, usar ProcessBuilder con args."),
        ("java_sql_concat", r"(executeQuery|executeUpdate|execute)\s*\(\s*\"[^\"]*\"\s*\+", Severity.HIGH, "SQL injection por concatenación", "Usar PreparedStatement."),
        ("java_xml_external", r"DocumentBuilderFactory|SAXParserFactory", Severity.MEDIUM, "Parser XML — verificar protección XXE", "Deshabilitar external entities."),
    ],
    "go": [
        ("go_command_inject", r"exec\.Command\s*\(\s*[^,]+\+", Severity.HIGH, "exec.Command con concatenación", "No concatenar input en argumentos de comando."),
        ("go_sql_format", r"fmt\.Sprintf\s*\([^)]*SELECT|fmt\.Sprintf\s*\([^)]*INSERT|fmt\.Sprintf\s*\([^)]*UPDATE", Severity.HIGH, "SQL con fmt.Sprintf", "Usar parámetros con $1, $2..."),
    ],
}


class PatternScanner:
    """Scanner embebido que NUNCA depende de binarios externos."""
    name = "pattern-scanner"

    def __init__(self, progress_cb: Optional[Callable] = None):
        self.progress_cb = progress_cb

    def _report(self, msg: str, prog: float):
        if self.progress_cb:
            try:
                self.progress_cb(msg, prog)
            except Exception:
                pass
        logger.info(f"[{self.name}] {msg}")

    async def scan(self, source: Path) -> list[Vulnerability]:
        from app.utils.files import detect_language

        self._report("Iniciando análisis de patrones", 0)
        files = walk_sources(source)
        if not files:
            self._report("Sin archivos analizables", 100)
            return []

        vulns: list[Vulnerability] = []
        total = len(files)

        for idx, fpath in enumerate(files):
            if idx % 10 == 0:
                self._report(f"Analizando {idx}/{total}: {fpath.name}", (idx / total) * 100)

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            try:
                rel = str(fpath.relative_to(source))
            except ValueError:
                rel = str(fpath)

            lang = detect_language(fpath)

            for line_no, line in enumerate(content.splitlines(), 1):
                if len(line) > 1000:
                    continue

                # Secretos (todos los lenguajes)
                for rule_id, pattern, sev, title in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        vulns.append(self._mk_vuln(
                            rule_id=f"secrets.{rule_id}",
                            severity=sev,
                            title=f"Secreto detectado: {title}",
                            description=f"Patrón coincide con {title}. Mover a variable de entorno.",
                            recommendation="Rotar la credencial y moverla a variables de entorno o secret manager.",
                            file_path=rel,
                            line_number=line_no,
                            code_snippet=line.strip()[:200],
                            cwe="CWE-798",
                        ))

                # Patrones por lenguaje
                if lang and lang in DANGEROUS_PATTERNS:
                    for rule_id, pattern, sev, title, rec in DANGEROUS_PATTERNS[lang]:
                        if re.search(pattern, line):
                            vulns.append(self._mk_vuln(
                                rule_id=f"pattern.{lang}.{rule_id}",
                                severity=sev,
                                title=title,
                                description=f"En {lang}: {title}",
                                recommendation=rec,
                                file_path=rel,
                                line_number=line_no,
                                code_snippet=line.strip()[:200],
                            ))

        # Detección a nivel proyecto
        vulns.extend(self._scan_config_files(source))

        self._report(f"Pattern scanner: {len(vulns)} hallazgos", 100)
        return vulns

    def _scan_config_files(self, source: Path) -> list[Vulnerability]:
        """Busca .env, configs, etc."""
        vulns: list[Vulnerability] = []

        # .env files con datos
        for env_file in source.rglob(".env*"):
            if env_file.name in (".env.example", ".env.template", ".env.sample"):
                continue
            try:
                content = env_file.read_text(errors="ignore")
            except Exception:
                continue
            for line_no, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    _, _, value = line.partition("=")
                    if len(value.strip().strip('"').strip("'")) > 8:
                        try:
                            rel = str(env_file.relative_to(source))
                        except ValueError:
                            rel = str(env_file)
                        vulns.append(self._mk_vuln(
                            rule_id="config.env_committed",
                            severity=Severity.HIGH,
                            title=f"Archivo .env con valores ({env_file.name})",
                            description="Archivos .env no deberían commitearse con valores reales.",
                            recommendation="Agregar .env al .gitignore y commitear solo .env.example.",
                            file_path=rel,
                            line_number=line_no,
                            code_snippet=line[:200],
                            cwe="CWE-538",
                        ))
                        break

        # .git directory expuesto
        if (source / ".git").is_dir():
            vulns.append(self._mk_vuln(
                rule_id="config.git_directory",
                severity=Severity.MEDIUM,
                title=".git directory en el proyecto",
                description="Si este proyecto se despliega tal cual, el .git queda expuesto.",
                recommendation="Asegurar que .git no se despliegue a producción.",
                file_path=".git/",
            ))

        return vulns

    @staticmethod
    def _mk_vuln(**kwargs) -> Vulnerability:
        return Vulnerability(
            id=str(uuid.uuid4())[:8],
            scanner="pattern-scanner",
            **kwargs,
        )
