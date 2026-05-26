#!/usr/bin/env bash
# VulnScout — Unified Launcher
# Usage: ./start.sh [api|web|install]
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error(){ echo -e "${RED}[x]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

cleanup() {
    warn "Shutting down..."
    [ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null || true
    [ -n "${WEB_PID:-}" ] && kill "$WEB_PID" 2>/dev/null || true
    exit 0
}
trap cleanup INT TERM

# Find Python
PYTHON=""
for cmd in python3 python; do
    command -v "$cmd" &>/dev/null && { PYTHON="$cmd"; break; }
done
if [ -z "$PYTHON" ]; then
    error "Python 3 not found. Install it first."
    exit 1
fi

# Find Node
NODE=""
for cmd in node nodejs; do
    command -v "$cmd" &>/dev/null && { NODE="$cmd"; break; }
done

# Ensure package installed
if ! $PYTHON -c "import src.scanner.engine" 2>/dev/null; then
    log "Installing VulnScout package..."
    $PYTHON -m pip install -e . --quiet --break-system-packages 2>/dev/null || \
    $PYTHON -m pip install -e . --quiet 2>/dev/null || \
    warn "Could not install via pip. Trying direct import..."
fi

MODE="${1:-web}"

case "$MODE" in
    install)
        log "Installing VulnScout..."
        $PYTHON -m pip install -e . --break-system-packages 2>/dev/null || \
        $PYTHON -m pip install -e . 2>/dev/null || true
        
        log "Installing web dependencies..."
        if [ -n "$NODE" ] && [ -f "web/package.json" ]; then
            cd web && npm install --silent 2>/dev/null && cd "$APP_DIR"
        fi
        
        log "Checking system tools..."
        command -v nmap &>/dev/null && log "nmap: found" || warn "nmap not found (optional for network scanning)"
        noir version &>/dev/null 2>&1 && log "Noir: found" || warn "Noir not found. Install: snap install noir"
        
        log "Installation complete!"
        ;;
    
    api)
        log "Starting API server..."
        info "API docs:  http://localhost:8000/docs"
        info "Dashboard: http://localhost:8000"
        exec $PYTHON -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
        ;;
    
    web|*)
        log "Starting API server on :8000..."
        $PYTHON -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload &
        API_PID=$!
        sleep 1
        
        if [ -n "$NODE" ] && [ -f "web/package.json" ]; then
            log "Starting Web Dashboard..."
            cd web
            npm install --silent 2>/dev/null
            npx vite --host 0.0.0.0 --port 5173 &
            WEB_PID=$!
            cd "$APP_DIR"
            info "Dashboard: http://localhost:5173"
            info "API docs:  http://localhost:8000/docs"
        else
            warn "Node.js not found or web/ missing. Running API only."
            info "Dashboard: http://localhost:8000"
        fi
        
        log "VulnScout is running. Press Ctrl+C to stop."
        wait
        ;;
esac
