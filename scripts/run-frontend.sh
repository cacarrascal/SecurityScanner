#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/frontend"
if [ ! -d "node_modules" ]; then
  echo "❌ No existe node_modules — ejecutá ./scripts/install.sh"; exit 1
fi
echo "🎨 Frontend → http://localhost:3000"
exec npm run dev
