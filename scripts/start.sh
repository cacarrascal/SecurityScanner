#!/usr/bin/env bash
# Arranca backend + frontend en paralelo. Ctrl+C los para a ambos.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

G='\033[0;32m'; B='\033[0;34m'; Y='\033[1;33m'; N='\033[0m'

if [ ! -d "$ROOT/backend/.venv" ] || [ ! -d "$ROOT/frontend/node_modules" ]; then
  echo -e "${Y}⚠ Falta instalación. Ejecutá:${N} ./scripts/install.sh"
  exit 1
fi

mkdir -p "$ROOT/logs"
BACK_LOG="$ROOT/logs/backend.log"
FRONT_LOG="$ROOT/logs/frontend.log"

echo -e "${B}╔════════════════════════════════════════╗${N}"
echo -e "${B}║   🛡  SecurityScanner — Arrancando    ║${N}"
echo -e "${B}╚════════════════════════════════════════╝${N}"

echo -e "${B}▶${N} Backend..."
(cd "$ROOT/backend" && source .venv/bin/activate && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload) > "$BACK_LOG" 2>&1 &
BACK_PID=$!

echo -e "${B}▶${N} Frontend..."
(cd "$ROOT/frontend" && exec npm run dev) > "$FRONT_LOG" 2>&1 &
FRONT_PID=$!

cleanup() {
  echo ""
  echo -e "${Y}🛑 Deteniendo...${N}"
  kill "$BACK_PID" 2>/dev/null || true
  kill "$FRONT_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo -e "${G}✓ Detenido${N}"
}
trap cleanup EXIT INT TERM

echo -n "  esperando backend"
for _ in $(seq 1 30); do
  if curl -sf http://localhost:8000/api/health >/dev/null 2>&1; then
    echo " ✓"
    break
  fi
  echo -n "."
  sleep 1
done

echo ""
echo -e "${G}✓ Backend  ${N}→ http://localhost:8000"
echo -e "${G}✓ Frontend ${N}→ http://localhost:3000"
echo -e "${G}✓ Swagger  ${N}→ http://localhost:8000/docs"
echo ""
echo -e "${Y}Ctrl+C para detener${N}"
echo ""

tail -f "$BACK_LOG" "$FRONT_LOG"
