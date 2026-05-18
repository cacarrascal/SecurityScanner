"""Configuración global — versión serverless."""

APP_NAME = "SecurityScanner"
VERSION = "2.0.0"

# Para correr local con uvicorn (no se usa en Vercel)
HOST = "0.0.0.0"
PORT = 8000

# Límite de subida — Vercel acepta hasta ~4.5 MB por body en Hobby
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB (local); en Vercel quedará limitado por la plataforma
SCAN_TIMEOUT = 50  # segundos por scanner externo (Vercel maxDuration es 60s)

# SSRF protection: bloquea IPs privadas/locales
BLOCKED_IP_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

CORS_ORIGINS = ["*"]
