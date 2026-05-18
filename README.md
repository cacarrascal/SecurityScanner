# 🛡 SecurityScanner (v2)

Análisis automático de seguridad y testing E2E **sin base de datos**, **sin auth**, **sin persistencia**.

> **Versión 2 — reescrita desde cero** para arreglar los bugs del Testing.zip original:
> - ✅ **El escaneo de archivos ahora corre realmente** (antes era mock que devolvía `status: started` sin escanear)
> - ✅ **El URL scanner detecta vulnerabilidades reales** (antes hardcodeaba `security_score: 92`)
> - ✅ **Sin Python `cgi.FieldStorage`** (deprecado, eliminado en 3.13)
> - ✅ **Path traversal bloqueado** en extracción de ZIPs (era CVE-2007-4559 latente)
> - ✅ **SSRF protection** en URL scans (bloquea IPs privadas)
> - ✅ **Sin arquitectura híbrida** Vite+Next+Vercel-Python (ahora: Next.js + FastAPI standalone)

---

## ✨ Lo que detecta

### Análisis de código
- **Secretos hardcodeados**: AWS keys, Google API keys, Slack tokens, GitHub tokens, Stripe, JWTs, passwords, DB URLs
- **Patrones peligrosos por lenguaje**:
  - Python: `eval`, `exec`, `pickle.loads`, `yaml.load`, `shell=True`, `os.system`, `verify=False`, MD5/SHA1
  - JS/TS: `eval`, `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, `new Function`, localStorage tokens
  - PHP: `eval`, `system`, `include` con variables, `unserialize`, SQL injection
  - Java: `Runtime.exec`, SQL concat, XML XXE
- **SQL injection** (concatenación de strings en queries)
- **XSS reflejado** (innerHTML, dangerouslySetInnerHTML)
- **CWE-798**: secrets in source
- **CWE-22**: path traversal
- **CWE-79**: XSS

### Dependencias
- Lee `requirements*.txt`, `pyproject.toml`, `package.json`, `composer.json`
- Match contra CVEs conocidos (Django, Flask, Lodash, Axios, Next.js, etc.)

### URL Scanner (el que estaba roto en Testing)
- Headers de seguridad faltantes (HSTS, CSP, X-Frame-Options, etc.)
- Cookies sin Secure/HttpOnly/SameSite
- Formularios POST sin CSRF token
- Mixed content (form HTTP en página HTTPS)
- Tecnologías detectadas (WordPress, Next.js, Django, etc.)
- **Paths comunes expuestos**: `.env`, `.git/`, `/admin`, `phpinfo.php`, backups SQL
- **XSS reflejado en query params**
- **Open redirects** (param `redirect`, `url`, `next`, etc.)
- **Stack traces / debug info** filtrado
- **Directory listing** habilitado
- **Métodos HTTP peligrosos** (TRACE, PUT, DELETE)
- Errores SQL/PHP/Oracle en respuesta
- **SSL/TLS** issues
- **Server leakage** (Server, X-Powered-By headers)

### Calidad
- Complejidad ciclomática
- Lines of code por lenguaje

---

## 🧱 Stack

**Backend**: Python 3.10+ · FastAPI · WebSocket · ReportLab · GitPython · httpx · BeautifulSoup
**Frontend**: Next.js 15 · React 18 · TailwindCSS · Axios · Recharts · Lucide

---

## 📋 Requisitos

| | versión | verificá con |
|---|---|---|
| Python | 3.10+ | `python3 --version` |
| Node.js | 18+ | `node --version` |
| npm | 9+ | `npm --version` |
| Git | cualquiera | `git --version` |

---

## 🚀 Instalación + arranque

```bash
./scripts/install.sh   # primera vez (3-5 min)
./scripts/start.sh     # arranca backend + frontend en una terminal
```

URLs:
- **Frontend** → http://localhost:3000
- **API** → http://localhost:8000
- **Swagger docs** → http://localhost:8000/docs

`Ctrl+C` detiene ambos servicios.

### O por separado (dos terminales)

```bash
./scripts/run-backend.sh    # terminal 1
./scripts/run-frontend.sh   # terminal 2
```

---

## 📁 Estructura

```
SecurityScanner/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI entry
│   │   ├── config.py
│   │   ├── api/                    # Endpoints REST + WS
│   │   │   ├── scans.py
│   │   │   ├── ws.py
│   │   │   └── health.py
│   │   ├── scanners/               # Scanners reales
│   │   │   ├── pattern_scanner.py  # Embebido, sin deps externas
│   │   │   ├── dependency_scanner.py
│   │   │   ├── complexity_scanner.py
│   │   │   └── external_scanners.py # Semgrep + Bandit (opcionales)
│   │   ├── services/
│   │   │   ├── orchestrator.py     # Pipeline principal
│   │   │   ├── url_scanner.py      # Scanner URL completo
│   │   │   └── ws_manager.py       # WebSocket broadcast
│   │   ├── reports/generator.py    # HTML/PDF/JSON
│   │   ├── models/schemas.py       # Pydantic
│   │   └── utils/                  # workspace, security, files
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.js             # Home (upload)
│   │   │   ├── url/page.js         # URL scan form
│   │   │   ├── git/page.js         # Git repo form
│   │   │   ├── scans/page.js       # Lista de scans
│   │   │   ├── scan/[scanId]/page.js     # Progreso en vivo
│   │   │   ├── results/[scanId]/page.js  # Resultados + reportes
│   │   │   ├── about/page.js
│   │   │   └── layout.js
│   │   ├── components/
│   │   │   ├── Sidebar.jsx
│   │   │   ├── Console.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   ├── VulnTable.jsx
│   │   │   └── ProgressBar.jsx
│   │   └── lib/api.js
│   ├── next.config.js              # Proxy /api → backend
│   └── package.json
├── scripts/
│   ├── install.sh
│   ├── start.sh                    # ← arranca todo
│   ├── run-backend.sh
│   ├── run-frontend.sh
│   └── cleanup.sh
└── README.md
```

---

## 🔌 API

| Método | Endpoint | Descripción |
|---|---|---|
| `POST` | `/api/scans/upload` | Subir ZIP/archivo (multipart) |
| `POST` | `/api/scans/git` | Clonar repo Git |
| `POST` | `/api/scans/url` | Escanear URL pública |
| `GET` | `/api/scans/{id}` | Resultado completo |
| `GET` | `/api/scans/` | Lista de scans activos |
| `DELETE` | `/api/scans/{id}` | Cancelar |
| `GET` | `/api/scans/{id}/report/{format}` | Descargar reporte (json/html/pdf) |
| `WS` | `/ws/scans/{id}` | Progreso en vivo |
| `GET` | `/api/health` | Healthcheck |
| `GET` | `/api/status` | Estado de scanners disponibles |

### Ejemplos

```bash
# URL scan
curl -X POST http://localhost:8000/api/scans/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "deep_scan": true}'

# Upload ZIP
curl -X POST http://localhost:8000/api/scans/upload \
  -F "file=@mi-proyecto.zip"

# Resultado
curl http://localhost:8000/api/scans/<scan_id>
```

---

## 🔒 Seguridad del propio SecurityScanner

| Vector | Protección |
|---|---|
| **Path traversal en ZIPs** | Validación de paths en `safe_extract_zip` |
| **Zip bomb** | Límite de tamaño descomprimido |
| **DoS por upload** | 500 MB máx, lectura por chunks |
| **SSRF en URL scan** | Bloqueo de IPs privadas (10.x, 192.168.x, 127.x, etc.) |
| **Filename injection** | Sanitización con whitelist de chars |
| **Workspace leakage** | UUIDs aleatorios + TTL 1h + cleanup auto |
| **Resource exhaustion** | Timeout por scanner (10 min) |

---

## 🐛 Troubleshooting

| Síntoma | Solución |
|---|---|
| "El scan se queda cargando" | Verificá `./logs/backend.log` — los scanners embebidos SIEMPRE corren |
| "URL dice 100% sin vulns" | Probá con `deep_scan: true` y mirá el tab "URL Scan" en resultados |
| `port already in use 8000` | Matá el proceso: `lsof -ti:8000 \| xargs kill -9` |
| `port already in use 3000` | `lsof -ti:3000 \| xargs kill -9` |
| WebSocket no conecta | Verificá que backend esté en `:8000` antes de abrir frontend |
| PDF no se genera | Reinstalá: `cd backend && source .venv/bin/activate && pip install reportlab` |

---

## 📜 Licencia

MIT. Para uso defensivo y pruebas autorizadas únicamente.
