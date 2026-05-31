#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Установка зависимостей для Minecraft Cheat Detector
#  Запустить ОДИН РАЗ на машине игрока перед первым сканированием
#  Использование:  sudo bash install.sh
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[91m'; YELLOW='\033[93m'; GREEN='\033[92m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${RESET} $1"; }
info() { echo -e "  ${CYAN}[..]${RESET} $1"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $1"; }
err()  { echo -e "  ${RED}[ERR]${RESET} $1"; }

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     MC Cheat Detector — Установка        ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"

# ─── Определяем пакетный менеджер ────────────────────────────────────────
detect_pm() {
    if   command -v pacman  &>/dev/null; then echo "pacman"
    elif command -v apt-get &>/dev/null; then echo "apt"
    elif command -v dnf     &>/dev/null; then echo "dnf"
    elif command -v yum     &>/dev/null; then echo "yum"
    elif command -v zypper  &>/dev/null; then echo "zypper"
    elif command -v apk     &>/dev/null; then echo "apk"
    else echo "unknown"
    fi
}

install_pkg() {
    local pkg_pacman="$1" pkg_apt="$2" pkg_dnf="$3"
    case "$PM" in
        pacman)  pacman -Sy --noconfirm "$pkg_pacman" ;;
        apt)     apt-get install -y -q "$pkg_apt" ;;
        dnf)     dnf install -y "$pkg_dnf" ;;
        yum)     yum install -y "$pkg_dnf" ;;
        zypper)  zypper install -y "$pkg_apt" ;;
        apk)     apk add --no-cache "$pkg_apt" ;;
        *)       err "Пакетный менеджер не определён. Установите $pkg_apt вручную."; return 1 ;;
    esac
}

PM=$(detect_pm)
info "Пакетный менеджер: ${BOLD}${PM}${RESET}"
echo ""

# ─── 1. Python 3 ─────────────────────────────────────────────────────────
info "Проверка Python3..."
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1)
    ok "Python3 уже установлен: $PY_VER"
else
    info "Устанавливаю Python3..."
    if install_pkg "python" "python3" "python3"; then
        ok "Python3 установлен: $(python3 --version)"
    else
        err "Не удалось установить Python3"
        exit 1
    fi
fi

# ─── 2. binutils (strings) ───────────────────────────────────────────────
info "Проверка утилиты strings (binutils)..."
if command -v strings &>/dev/null; then
    ok "strings уже установлен"
else
    info "Устанавливаю binutils..."
    if install_pkg "binutils" "binutils" "binutils"; then
        ok "binutils установлен"
    else
        warn "binutils не установлен — strings-сканирование будет ограничено"
    fi
fi

# ─── 3. git (опционально) ─────────────────────────────────────────────────
info "Проверка git..."
if command -v git &>/dev/null; then
    ok "git уже установлен"
else
    info "Устанавливаю git..."
    if install_pkg "git" "git" "git"; then
        ok "git установлен"
    else
        warn "git не установлен — обновление через git clone недоступно"
    fi
fi

# ─── 4. openssh (scp) ─────────────────────────────────────────────────────
info "Проверка SSH/SCP..."
if command -v scp &>/dev/null; then
    ok "scp доступен"
else
    info "Устанавливаю openssh..."
    install_pkg "openssh" "openssh-client" "openssh-clients" || warn "SCP недоступен"
fi

echo ""
echo -e "${GREEN}${BOLD}  Установка завершена!${RESET}"
echo ""
echo -e "  Запустите сканер:"
echo -e "  ${BOLD}sudo python3 scan.py --user <имя_пользователя>${RESET}"
echo ""
