#!/usr/bin/env python3
"""
Minecraft Cheat Detector — Linux Edition
Запуск: sudo python3 scan.py --user <username>
"""

import os
import sys
import argparse
import http.server
import threading
from pathlib import Path
from datetime import datetime

# Добавляем корневую папку в путь
sys.path.insert(0, str(Path(__file__).parent))

from detectors.processes    import ProcessScanner
from detectors.mods         import ModScanner
from detectors.native       import NativeScanner
from detectors.network      import NetworkScanner
from detectors.filesystem   import FilesystemScanner
from detectors.integrity    import IntegrityChecker
from detectors.strings_scan import StringsScanner
from report.generator       import ReportGenerator

RESET  = '\033[0m'
RED    = '\033[91m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
DIM    = '\033[2m'

RISK_COLORS = {
    'clean':      GREEN,
    'suspicious': YELLOW,
    'danger':     RED,
    'unknown':    DIM,
}


def banner():
    print(f"""{CYAN}{BOLD}
  ███╗   ███╗ ██████╗    ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
  ████╗ ████║██╔════╝   ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ██╔████╔██║██║        ██║     ███████║█████╗  ██║     █████╔╝
  ██║╚██╔╝██║██║        ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗
  ██║ ╚═╝ ██║╚██████╗   ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═╝     ╚═╝ ╚═════╝    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
{RESET}{DIM}  Minecraft Cheat Detector — Linux Edition{RESET}
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description='Minecraft Cheat Detector — сканирует систему Linux на читы',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--user', '-u',
        required=True,
        help='Имя пользователя для проверки (например: player1)'
    )
    parser.add_argument(
        '--output', '-o',
        default='/tmp/mc_report.html',
        help='Путь для сохранения HTML-отчёта (по умолчанию: /tmp/mc_report.html)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8888,
        help='Порт HTTP-сервера для просмотра отчёта (по умолчанию: 8888)'
    )
    parser.add_argument(
        '--no-serve',
        action='store_true',
        help='Не запускать HTTP-сервер после сканирования'
    )
    return parser.parse_args()


def run_scanner(label, scanner_cls, username):
    print(f'  {DIM}[...]{RESET} {label}', end='', flush=True)
    try:
        result = scanner_cls(username).scan()
        risk = result.get('risk', 'unknown')
        color = RISK_COLORS.get(risk, DIM)
        label_map = {'clean': 'ЧИСТО', 'suspicious': 'ПОДОЗРИТЕЛЬНО', 'danger': 'ОПАСНОСТЬ', 'unknown': 'НЕИЗВЕСТНО'}
        print(f'\r  {color}[{label_map.get(risk, risk.upper())}]{RESET} {label}')
        return result
    except Exception as e:
        print(f'\r  {RED}[ОШИБКА]{RESET} {label}')
        return {'error': str(e), 'findings': [], 'risk': 'unknown', 'name': label, 'description': ''}


def serve_report(output_path, port):
    report_dir  = str(Path(output_path).parent)
    report_file = Path(output_path).name

    class SilentHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=report_dir, **kwargs)
        def log_message(self, *args):
            pass

    try:
        server = http.server.HTTPServer(('0.0.0.0', port), SilentHandler)
    except OSError as e:
        print(f'\n{RED}[!] Не удалось запустить сервер на порту {port}: {e}{RESET}')
        print(f'    Откройте отчёт вручную: {output_path}')
        return

    print(f'\n{CYAN}{"─"*55}{RESET}')
    print(f'{BOLD}  Сервер отчёта запущен{RESET}')
    print(f'{CYAN}{"─"*55}{RESET}')
    print(f'  Порт:   {BOLD}{port}{RESET}')
    print(f'  Файл:   {output_path}')
    print()
    print(f'  {YELLOW}Для просмотра в браузере выполните на своей машине:{RESET}')
    print(f'  {BOLD}ssh -L {port}:localhost:{port} user@<IP>{RESET}')
    print(f'  Затем откройте: {CYAN}http://localhost:{port}/{report_file}{RESET}')
    print(f'\n  {DIM}Ctrl+C — остановить сервер{RESET}\n')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f'\n{DIM}[*] Сервер остановлен.{RESET}')


def main():
    args = parse_args()

    if os.geteuid() != 0:
        print(f'{YELLOW}[!] Предупреждение: запуск без root. Часть проверок (ptrace, /proc/maps других процессов) будет ограничена.{RESET}')
        print(f'    Рекомендуется: {BOLD}sudo python3 scan.py --user {args.user}{RESET}\n')

    banner()

    print(f'{BOLD}  Цель:{RESET} {args.user}')
    print(f'{BOLD}  Время:{RESET} {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print(f'\n{CYAN}{"─"*55}{RESET}')
    print(f'  Запуск сканеров...\n')

    scanners = [
        ('Сканер процессов',              ProcessScanner),
        ('Сканер модов (JAR)',             ModScanner),
        ('Сканер native-библиотек (.so)', NativeScanner),
        ('Сканер сети',                   NetworkScanner),
        ('Сканер файловой системы',       FilesystemScanner),
        ('Проверка целостности клиента',  IntegrityChecker),
        ('Сканер строк (strings)',        StringsScanner),
    ]

    results = {}
    key_map = ['processes', 'mods', 'native', 'network', 'filesystem', 'integrity', 'strings']

    for i, (label, cls) in enumerate(scanners):
        key = key_map[i]
        results[key] = run_scanner(label, cls, args.user)

    # Итоговый риск
    order = {'clean': 0, 'suspicious': 1, 'danger': 2, 'unknown': -1}
    overall = max(results.values(), key=lambda d: order.get(d.get('risk', 'unknown'), -1))
    overall_risk = overall.get('risk', 'unknown')
    risk_color = RISK_COLORS.get(overall_risk, DIM)
    risk_names = {'clean': 'ЧИСТО', 'suspicious': 'ПОДОЗРИТЕЛЬНО', 'danger': 'ОПАСНОСТЬ', 'unknown': 'НЕИЗВЕСТНО'}

    print(f'\n{CYAN}{"─"*55}{RESET}')
    print(f'  Итоговый результат: {risk_color}{BOLD}{risk_names.get(overall_risk, overall_risk)}{RESET}')
    print(f'{CYAN}{"─"*55}{RESET}\n')

    # Генерация отчёта
    print(f'  Генерация HTML-отчёта...', end='', flush=True)
    try:
        gen  = ReportGenerator(results, args.user)
        html = gen.generate()
        Path(args.output).write_text(html, encoding='utf-8')
        print(f'\r  {GREEN}[OK]{RESET} Отчёт сохранён: {args.output}')
    except Exception as e:
        print(f'\r  {RED}[!]{RESET} Ошибка генерации отчёта: {e}')
        sys.exit(1)

    if not args.no_serve:
        serve_report(args.output, args.port)
    else:
        print(f'\n  Откройте файл в браузере: {args.output}')


if __name__ == '__main__':
    main()
