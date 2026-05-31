#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Minecraft Cheat Detector — Запуск от администратора
#  Просто запусти: ./run.sh
#  Скрипт сам спросит IP, юзернейм и пароль
# ─────────────────────────────────────────────────────────────────────────────

set -e

RED='\033[91m'; YELLOW='\033[93m'; GREEN='\033[92m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'; DIM='\033[2m'

REMOTE_DIR="/tmp/mc-checker"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_LOCAL="/tmp/mc_report_$(date +%Y%m%d_%H%M%S).html"
SSH_SOCKET="/tmp/mc_ssh_ctl_$$"

# Очистка сокета при выходе
cleanup() { rm -f "$SSH_SOCKET"; }
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────────────

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     Minecraft Cheat Detector — SSH       ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"

# ─── Запрашиваем данные ───────────────────────────────────────────────────
echo -e "  Введи данные игрока:\n"

read -rp "  IP-адрес:    " PLAYER_IP
read -rp "  Юзернейм:   " PLAYER_USER
read -rsp "  Пароль SSH:  " PLAYER_PASS
echo ""
echo ""

# Проверка заполнения
if [[ -z "$PLAYER_IP" || -z "$PLAYER_USER" || -z "$PLAYER_PASS" ]]; then
    echo -e "  ${RED}[!]${RESET} IP, юзернейм и пароль обязательны."
    exit 1
fi

SSH_TARGET="${PLAYER_USER}@${PLAYER_IP}"

echo -e "  Цель:         ${BOLD}${SSH_TARGET}${RESET}"
echo -e "  Отчёт:        ${BOLD}${REPORT_LOCAL}${RESET}"
echo ""

# ─── Проверка sshpass ─────────────────────────────────────────────────────
if ! command -v sshpass &>/dev/null; then
    echo -e "  ${YELLOW}[!]${RESET} sshpass не найден. Устанавливаю..."
    if   command -v pacman  &>/dev/null; then pacman -Sy --noconfirm sshpass
    elif command -v apt-get &>/dev/null; then apt-get install -y -q sshpass
    elif command -v dnf     &>/dev/null; then dnf install -y sshpass
    elif command -v brew    &>/dev/null; then brew install hudochenkov/sshpass/sshpass
    else
        echo -e "  ${RED}[!]${RESET} Установи sshpass вручную и запусти снова."
        exit 1
    fi
fi

# Алиасы с паролем (пароль вводится только здесь — дальше всё через них)
_ssh()  { sshpass -p "$PLAYER_PASS" ssh  -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$SSH_TARGET" "$@"; }
_scp()  { sshpass -p "$PLAYER_PASS" scp  -o StrictHostKeyChecking=no -r "$@"; }
_ssht() { sshpass -p "$PLAYER_PASS" ssh  -o StrictHostKeyChecking=no -o ConnectTimeout=10 -t "$SSH_TARGET" "$@"; }

# ─── 1. Проверка соединения ───────────────────────────────────────────────
echo -e "  ${YELLOW}[1/4]${RESET} Подключение к ${SSH_TARGET}..."
if ! _ssh "echo ok" &>/dev/null; then
    echo -e "  ${RED}[!]${RESET} Не удалось подключиться. Проверь IP и пароль."
    exit 1
fi
echo -e "  ${GREEN}[OK]${RESET} Соединение установлено"

# ─── 2. Установка Python3 и зависимостей ─────────────────────────────────
echo -e "  ${YELLOW}[2/4]${RESET} Проверка Python3 и binutils..."
_ssh bash << 'ENDSSH'
install_pkg() {
    local p1="$1" p2="$2"
    if   command -v pacman  &>/dev/null; then pacman -Sy --noconfirm "$p1" 2>/dev/null
    elif command -v apt-get &>/dev/null; then apt-get install -y -q "$p2" 2>/dev/null
    elif command -v dnf     &>/dev/null; then dnf install -y "$p2" 2>/dev/null
    elif command -v yum     &>/dev/null; then yum install -y "$p2" 2>/dev/null
    fi
}
command -v python3 &>/dev/null || install_pkg python python3
command -v strings &>/dev/null || install_pkg binutils binutils
echo "python3=$(python3 --version 2>&1) strings=$(command -v strings &>/dev/null && echo ok || echo missing)"
ENDSSH
echo -e "  ${GREEN}[OK]${RESET} Зависимости в порядке"

# ─── 3. Копирование сканера ───────────────────────────────────────────────
echo -e "  ${YELLOW}[3/4]${RESET} Копирую сканер на машину игрока..."
_ssh "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"
_scp \
    "$SCRIPT_DIR/scan.py" \
    "$SCRIPT_DIR/detectors" \
    "$SCRIPT_DIR/report" \
    "$SCRIPT_DIR/signatures" \
    "${SSH_TARGET}:${REMOTE_DIR}/"
echo -e "  ${GREEN}[OK]${RESET} Файлы скопированы"

# ─── 4. Сканирование ─────────────────────────────────────────────────────
echo -e "  ${YELLOW}[4/4]${RESET} Запуск сканирования...\n"
echo -e "${DIM}──────────────────────────────────────────────${RESET}"

_ssht "cd $REMOTE_DIR && sudo python3 scan.py --user '$PLAYER_USER' --no-serve --output /tmp/mc_report.html" || true

echo -e "${DIM}──────────────────────────────────────────────${RESET}\n"

# ─── 5. Скачивание и открытие отчёта ─────────────────────────────────────
echo -e "  ${CYAN}Скачиваю HTML-отчёт...${RESET}"
_scp "${SSH_TARGET}:/tmp/mc_report.html" "$REPORT_LOCAL"

echo -e "  ${GREEN}[OK]${RESET} Отчёт: ${BOLD}${REPORT_LOCAL}${RESET}"
echo -e "  ${CYAN}Открываю в браузере...${RESET}\n"

if   command -v xdg-open &>/dev/null; then xdg-open "$REPORT_LOCAL" &
elif command -v open     &>/dev/null; then open "$REPORT_LOCAL"
elif command -v wslview  &>/dev/null; then wslview "$REPORT_LOCAL"
elif [[ -n "$WSL_DISTRO_NAME"      ]]; then cmd.exe /C "start $(wslpath -w "$REPORT_LOCAL")"
else
    echo -e "  ${YELLOW}Открой файл вручную:${RESET} ${REPORT_LOCAL}"
fi

echo -e "  ${GREEN}${BOLD}Готово!${RESET}\n"
