#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Minecraft Cheat Detector — Запуск от администратора
#  Просто запусти: ./run.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e

RED='\033[91m'; YELLOW='\033[93m'; GREEN='\033[92m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'; DIM='\033[2m'

REMOTE_DIR="/tmp/mc-checker"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_LOCAL="/tmp/mc_report_$(date +%Y%m%d_%H%M%S).html"
SSH_SOCKET="/tmp/mc_ssh_ctl_$$"

cleanup() { ssh -o ControlPath="$SSH_SOCKET" -O exit "$SSH_TARGET" 2>/dev/null; rm -f "$SSH_SOCKET"; }
trap cleanup EXIT

# ─── Шапка ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     Minecraft Cheat Detector — SSH       ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"

# ─── Запрашиваем данные ───────────────────────────────────────────────────────
echo -e "  Введи данные игрока:\n"
read -rp "  IP-адрес:   " PLAYER_IP
read -rp "  Юзернейм:  " PLAYER_USER
echo ""

SSH_TARGET="${PLAYER_USER}@${PLAYER_IP}"

echo -e "  Цель:    ${BOLD}${SSH_TARGET}${RESET}"
echo -e "  Отчёт:   ${BOLD}${REPORT_LOCAL}${RESET}"
echo ""

# Общие опции SSH — ControlMaster держит соединение открытым
# Пароль спрашивается ОДИН РАЗ при первом подключении
SSH_OPTS=(
    -o "ControlMaster=auto"
    -o "ControlPath=$SSH_SOCKET"
    -o "ControlPersist=300"
    -o "StrictHostKeyChecking=no"
    -o "ConnectTimeout=10"
)
SCP_OPTS=(
    -o "ControlPath=$SSH_SOCKET"
    -o "StrictHostKeyChecking=no"
)

_ssh()  { ssh  "${SSH_OPTS[@]}" "$SSH_TARGET" "$@"; }
_ssht() { ssh  "${SSH_OPTS[@]}" -t "$SSH_TARGET" "$@"; }
_scp()  { scp  "${SCP_OPTS[@]}" "$@"; }

# ─── 1. Подключение (здесь спросит пароль — только один раз) ─────────────────
echo -e "  ${YELLOW}[1/4]${RESET} Подключение... ${DIM}(введи пароль SSH)${RESET}"
if ! _ssh "echo ok" > /dev/null; then
    echo -e "  ${RED}[!]${RESET} Не удалось подключиться. Проверь IP и пароль."
    exit 1
fi
echo -e "  ${GREEN}[OK]${RESET} Соединение установлено"

# ─── 2. Установка Python3 и binutils ─────────────────────────────────────────
echo -e "  ${YELLOW}[2/4]${RESET} Проверка Python3 и binutils..."
_ssh bash << 'ENDSSH'
install_pkg() {
    if   command -v pacman  &>/dev/null; then pacman -Sy --noconfirm "$1" 2>/dev/null
    elif command -v apt-get &>/dev/null; then apt-get install -y -q "$2" 2>/dev/null
    elif command -v dnf     &>/dev/null; then dnf install -y "$2" 2>/dev/null
    fi
}
command -v python3 &>/dev/null || install_pkg python python3
command -v strings &>/dev/null || install_pkg binutils binutils
python3 --version
ENDSSH
echo -e "  ${GREEN}[OK]${RESET} Зависимости установлены"

# ─── 3. Копирование сканера ───────────────────────────────────────────────────
echo -e "  ${YELLOW}[3/4]${RESET} Копирую сканер..."
_ssh "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"
_scp -r \
    "$SCRIPT_DIR/scan.py" \
    "$SCRIPT_DIR/detectors" \
    "$SCRIPT_DIR/report" \
    "$SCRIPT_DIR/signatures" \
    "${SSH_TARGET}:${REMOTE_DIR}/"
echo -e "  ${GREEN}[OK]${RESET} Файлы скопированы"

# ─── 4. Сканирование ─────────────────────────────────────────────────────────
echo -e "  ${YELLOW}[4/4]${RESET} Запуск сканирования...\n"
echo -e "${DIM}──────────────────────────────────────────────${RESET}"
_ssht "cd $REMOTE_DIR && sudo python3 scan.py --user '$PLAYER_USER' --no-serve --output /tmp/mc_report.html" || true
echo -e "${DIM}──────────────────────────────────────────────${RESET}\n"

# ─── Скачивание и открытие отчёта ────────────────────────────────────────────
echo -e "  ${CYAN}Скачиваю отчёт...${RESET}"
_scp "${SSH_TARGET}:/tmp/mc_report.html" "$REPORT_LOCAL"
echo -e "  ${GREEN}[OK]${RESET} Отчёт: ${BOLD}${REPORT_LOCAL}${RESET}"
echo -e "  ${CYAN}Открываю в браузере...${RESET}\n"

if   command -v xdg-open &>/dev/null; then xdg-open "$REPORT_LOCAL" &
elif command -v open     &>/dev/null; then open "$REPORT_LOCAL"
elif command -v wslview  &>/dev/null; then wslview "$REPORT_LOCAL"
elif [[ -n "$WSL_DISTRO_NAME"      ]]; then cmd.exe /C "start $(wslpath -w "$REPORT_LOCAL")"
elif [[ "$OSTYPE" == "msys"        ]]; then start "$REPORT_LOCAL" 2>/dev/null || cmd //C "start $(cygpath -w "$REPORT_LOCAL")"
else
    echo -e "  ${YELLOW}Открой файл вручную:${RESET} ${REPORT_LOCAL}"
fi

echo -e "  ${GREEN}${BOLD}Готово!${RESET}\n"
