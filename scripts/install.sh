#!/usr/bin/env bash
# SecurityScanner — Instalación local completa
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'

echo -e "${B}╔════════════════════════════════════════╗${N}"
echo -e "${B}║   🛡  SecurityScanner — Instalación  ║${N}"
echo -e "${B}╚════════════════════════════════════════╝${N}"
echo ""

echo -e "${B}▶ Verificando dependencias del sistema...${N}"
missing=()
check() {
  if command -v "$1" >/dev/null 2>&1; then
    echo -e "  ${G}✓${N} $1"
  else
    echo -e "  ${R}✗${N} $1 — falta"
    missing+=("$2")
  fi
}
check python3 "Python 3.10+ (python.org)"
check node "Node.js 18+ (nodejs.org)"
check npm "npm (viene con Node)"
check git "git"

if [ ${#missing[@]} -gt 0 ]; then
  echo ""
  echo -e "${R}Faltan dependencias:${N}"
  for d in "${missing[@]}"; do echo "  • $d"; done
  exit 1
fi

echo ""
echo -e "${B}▶ Backend (Python venv)...${N}"
cd "$ROOT/backend"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip --quiet
echo "  Instalando paquetes Python (3-5 min)..."
pip install -r requirements.txt
deactivate
echo -e "  ${G}✓${N} Backend listo"

echo ""
echo -e "${B}▶ Frontend (npm)...${N}"
cd "$ROOT/frontend"
npm install --no-audit --no-fund
echo -e "  ${G}✓${N} Frontend listo"

cd "$ROOT"
mkdir -p /tmp/carlos_workspaces logs

echo ""
echo -e "${G}╔════════════════════════════════════════╗${N}"
echo -e "${G}║   ✅  Instalación completa             ║${N}"
echo -e "${G}╚════════════════════════════════════════╝${N}"
echo ""
echo -e "${B}Arrancar todo en una terminal:${N}"
echo "  ./scripts/start.sh"
echo ""
echo -e "${B}URLs cuando arranque:${N}"
echo "  Frontend → http://localhost:3000"
echo "  API      → http://localhost:8000"
echo "  Docs     → http://localhost:8000/docs"
echo ""
