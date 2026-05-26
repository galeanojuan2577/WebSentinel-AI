#!/usr/bin/env bash
# VulnScout — Desktop GUI Launcher
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

# Use python3 explicitly (systems where `python` is not available)
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[ERROR] Python 3 not found. Install it first."
    exit 1
fi

# Ensure package is installed
if ! $PYTHON -c "import src.scanner.engine" 2>/dev/null; then
    echo "[INFO] Installing VulnScout..."
    $PYTHON -m pip install -e . --quiet --break-system-packages 2>/dev/null || $PYTHON -m pip install -e . --quiet
fi

echo "[INFO] Starting VulnScout GUI..."
exec $PYTHON -m src.gui.main "$@"
