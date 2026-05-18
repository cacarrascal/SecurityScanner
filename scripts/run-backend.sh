#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
if [ ! -d ".venv" ]; then
  echo "❌ No existe .venv — ejecutá ./scripts/install.sh"; exit 1
fi
source .venv/bin/activate
echo "🚀 Backend → http://localhost:8000"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
