#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Minecraft Cheat Detector — Запуск от администратора
#  Просто запусти: ./run.sh
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[91m'; YELLOW='\033[93m'; GREEN='\033[92m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'; DIM='\033[2m'

REMOTE_DIR="/tmp/mc-checker"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT_DIR="/c/Users/admin/Desktop/Check"
mkdir -p "$REPORT_DIR"
REPORT_LOCAL=""  # будет задан после ввода юзернейма
TEMP_KEY="${TEMP:-/tmp}/mc_tmp_key_$$"

# Удаляем временный ключ при выходе
cleanup() {
    if [[ -n "$SSH_TARGET" && -f "$TEMP_KEY" ]]; then
        # Удаляем ключ с удалённой машины
        KEY_COMMENT=$(awk '{print $3}' "${TEMP_KEY}.pub" 2>/dev/null)
        ssh -i "$TEMP_KEY" -o StrictHostKeyChecking=no -o BatchMode=yes \
            "$SSH_TARGET" \
            "sed -i '/mc_tmp/d' ~/.ssh/authorized_keys 2>/dev/null" 2>/dev/null || true
    fi
    rm -f "$TEMP_KEY" "${TEMP_KEY}.pub"
}
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

# Убираем \r (Git Bash на Windows добавляет их в конец read)
PLAYER_IP="${PLAYER_IP//$'\r'/}"
PLAYER_IP="${PLAYER_IP// /}"
PLAYER_USER="${PLAYER_USER//$'\r'/}"
PLAYER_USER="${PLAYER_USER// /}"

SSH_TARGET="${PLAYER_USER}@${PLAYER_IP}"
REPORT_LOCAL="${REPORT_DIR}/mc_report_${PLAYER_USER}_$(date +%Y%m%d_%H%M%S).html"

echo ""
echo -e "  Цель:    ${BOLD}${SSH_TARGET}${RESET}"
echo -e "  Отчёт:   ${BOLD}${REPORT_LOCAL}${RESET}"
echo ""

SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes)

# ─── Генерируем временный SSH-ключ ───────────────────────────────────────────
echo -e "  ${DIM}Создаю временный SSH-ключ...${RESET}"
ssh-keygen -t ed25519 -f "$TEMP_KEY" -N "" -C "mc_tmp" -q

# ─── Копируем ключ на удалённую машину (здесь спросит пароль — ОДИН РАЗ) ─────
echo -e "  ${YELLOW}[1/4]${RESET} Подключение ${DIM}(введи пароль SSH — больше не понадобится)${RESET}"
echo ""

# Копируем pub-ключ вручную (работает везде без ssh-copy-id)
PUB_KEY=$(cat "${TEMP_KEY}.pub")
if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$SSH_TARGET" \
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$PUB_KEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"; then
    echo ""
    echo -e "  ${RED}[!] Не удалось подключиться к ${SSH_TARGET}${RESET}"
    echo -e "  ${YELLOW}Возможные причины:${RESET}"
    echo -e "     • SSH не запущен на машине игрока"
    echo -e "       ${DIM}Исправление: sudo service ssh start  (или sudo systemctl start sshd)${RESET}"
    echo -e "     • Неверный IP или пароль"
    echo -e "     • Порт 22 заблокирован файрволом"
    exit 1
fi

echo ""
echo -e "  ${GREEN}[OK]${RESET} Подключение установлено"

# Теперь все команды через ключ — пароль больше не нужен
_ssh()  { ssh  "${SSH_OPTS[@]}" -i "$TEMP_KEY" "$SSH_TARGET" "$@"; }
_ssht() { ssh  "${SSH_OPTS[@]}" -i "$TEMP_KEY" -t "$SSH_TARGET" "$@"; }
_scp()  { scp  -o StrictHostKeyChecking=no -i "$TEMP_KEY" "$@"; }

# ─── 2. Установка Python3 и binutils ─────────────────────────────────────────
echo -e "  ${YELLOW}[2/4]${RESET} Проверка Python3 и binutils..."
_ssh bash << 'ENDSSH'
install_pkg() {
    if   command -v pacman  &>/dev/null; then sudo pacman -Sy --noconfirm "$1" 2>/dev/null
    elif command -v apt-get &>/dev/null; then sudo apt-get install -y -q "$2" 2>/dev/null
    elif command -v dnf     &>/dev/null; then sudo dnf install -y "$2" 2>/dev/null
    fi
}
command -v python3 &>/dev/null || install_pkg python python3
command -v strings &>/dev/null || install_pkg binutils binutils
python3 --version 2>&1
ENDSSH
echo -e "  ${GREEN}[OK]${RESET} Зависимости в порядке"

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

if   command -v xdg-open &>/dev/null; then xdg-open  "$REPORT_LOCAL" &
elif command -v open     &>/dev/null; then open       "$REPORT_LOCAL"
elif command -v wslview  &>/dev/null; then wslview    "$REPORT_LOCAL"
elif [[ -n "$WSL_DISTRO_NAME"      ]]; then cmd.exe /C "start $(wslpath -w "$REPORT_LOCAL")"
elif [[ "$OSTYPE" == "msys"        ]]; then cmd //C "start $(cygpath -w "$REPORT_LOCAL")"
else echo -e "  ${YELLOW}Открой вручную:${RESET} ${REPORT_LOCAL}"
fi

echo -e "  ${GREEN}${BOLD}Готово!${RESET}\n"
