#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "🧹 Limpiando..."
rm -rf /tmp/carlos_workspaces/* 2>/dev/null || true
rm -rf "$ROOT/logs"/*.log 2>/dev/null || true
find "$ROOT/backend" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$ROOT/backend" -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
rm -rf "$ROOT/frontend/.next" 2>/dev/null || true
echo "✅ Listo"
