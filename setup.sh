#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}✅${NC} $1"; }
fail() { echo -e "  ${RED}❌${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; }
info() { echo -e "  $1"; }

echo
echo -e "  ${GREEN}tunnelvault setup${NC}"
echo -e "  ${DIM}─────────────────${NC}"
echo

# --- Python ---
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        major=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo 0)
        minor=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo 0)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON="$cmd"
            ok "Python $ver ($cmd)"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    fail "Python 3.10+ не найден"
    echo -e "  ${DIM}brew install python@3.12  или  apt install python3${NC}"
    exit 1
fi

# --- venv ---
if [ ! -d .venv ]; then
    info "Создаю виртуальное окружение..."
    if command -v uv &>/dev/null; then
        uv venv -q
    else
        "$PYTHON" -m venv .venv
    fi
    ok "venv создан"
else
    ok "venv уже есть"
fi

# --- deps ---
info "Устанавливаю зависимости..."
if command -v uv &>/dev/null; then
    uv pip install -q tomli 2>/dev/null || true
else
    .venv/bin/pip install -q tomli 2>/dev/null || true
fi
ok "Зависимости установлены"

# --- System tools ---
echo
echo -e "  ${DIM}Системные утилиты:${NC}"
MISSING=0

check_tool() {
    local name="$1"
    local install_hint="${2:-}"
    if command -v "$name" &>/dev/null; then
        ok "$name"
    else
        fail "$name не найден${install_hint:+  ${DIM}($install_hint)${NC}}"
        MISSING=$((MISSING + 1))
    fi
}

check_tool openvpn       "brew install openvpn"
check_tool openfortivpn  "brew install openfortivpn"
check_tool sing-box      "https://sing-box.sagernet.org"
check_tool openssl       "brew install openssl"
check_tool curl
check_tool nc

# --- Config files ---
echo
echo -e "  ${DIM}Конфиги:${NC}"

if [ -f defaults.toml ]; then
    ok "defaults.toml"
else
    fail "defaults.toml не найден"
    MISSING=$((MISSING + 1))
fi

if [ -f "$SCRIPT_DIR/client.ovpn" ] || [ -f "$SCRIPT_DIR/titov-pc.ovpn" ]; then
    ok "OpenVPN конфиг"
else
    warn "OpenVPN конфиг (.ovpn) не найден ${DIM}(wizard спросит)${NC}"
fi

if [ -f piklema.json ]; then
    ok "piklema.json"
else
    warn "piklema.json не найден ${DIM}(wizard спросит)${NC}"
fi

# --- Make tv executable ---
chmod +x "$SCRIPT_DIR/tvpn" 2>/dev/null || true

# --- Summary ---
echo
if [ "$MISSING" -eq 0 ]; then
    echo -e "  ${GREEN}Готово!${NC} Запуск:"
    echo
    echo -e "    ${DIM}sudo ./tvpn${NC}              # подключить"
    echo -e "    ${DIM}sudo ./tvpn --disconnect${NC}  # отключить"
    echo
else
    warn "$MISSING проблем. Установи недостающее и запусти setup.sh снова."
    echo
fi
