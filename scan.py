#!/usr/bin/env python3
"""
PT Check — Windows Edition
Запуск: python scan.py [--user <username>]
Рекомендуется запуск от имени администратора.
"""

import os
import sys

# Принудительно UTF-8 для вывода в Windows-терминале
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import ctypes
import argparse
import webbrowser
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import http.server
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from detectors.processes    import ProcessScanner
from detectors.mods         import ModScanner
from detectors.native       import NativeScanner
from detectors.network      import NetworkScanner
from detectors.filesystem   import FilesystemScanner
from detectors.integrity    import IntegrityChecker
from detectors.strings_scan import StringsScanner
from detectors.artifacts         import ArtifactsScanner
from detectors.shellbag          import ShellBagScanner
from detectors.executedprograms  import ExecutedProgramsScanner
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


def _enable_ansi():
    """Включить ANSI escape-коды в Windows 10+ терминале."""
    try:
        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate_and_restart():
    """
    Перезапустить скрипт с правами администратора через UAC.
    Возвращает True если UAC-запрос был показан (пользователь нажал Да или Нет).
    """
    script = str(Path(__file__).resolve())
    # Пробрасываем все аргументы командной строки в поднятый процесс
    extra = ' '.join(f'"{a}"' for a in sys.argv[1:])
    params = f'"{script}" {extra}'.strip()
    ret = ctypes.windll.shell32.ShellExecuteW(
        None,           # hwnd
        "runas",        # verb — вызывает UAC
        sys.executable, # python.exe
        params,         # аргументы
        None,           # рабочая директория
        1,              # SW_SHOWNORMAL
    )
    return int(ret) > 32  # >32 = успех


def banner():
    print(f"""{CYAN}{BOLD}
  ██████╗ ████████╗    ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
  ██╔══██╗╚══██╔══╝   ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
  ██████╔╝   ██║      ██║     ███████║█████╗  ██║     █████╔╝
  ██╔═══╝    ██║      ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗
  ██║        ██║      ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═╝        ╚═╝       ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
{RESET}{DIM}  PT Check — Windows Edition{RESET}
""")


def parse_args():
    current_user = os.environ.get('USERNAME', '')
    temp_dir = os.environ.get('TEMP', os.environ.get('TMP', '.'))
    default_output = str(Path(temp_dir) / 'pt_report.html')

    parser = argparse.ArgumentParser(
        description='PT Check — сканирует Windows на читы Minecraft',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--user', '-u',
        default=current_user,
        help=f'Имя пользователя Windows (по умолчанию: {current_user})'
    )
    parser.add_argument(
        '--output', '-o',
        default=default_output,
        help=f'Путь для сохранения HTML-отчёта (по умолчанию: {default_output})'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8888,
        help='Порт HTTP-сервера (по умолчанию: 8888)'
    )
    parser.add_argument(
        '--no-serve',
        action='store_true',
        help='Открыть файл напрямую, без HTTP-сервера'
    )
    return parser.parse_args()


def run_scanner(label, scanner_cls, username, lock=None):
    def _print(msg):
        if lock:
            with lock:
                print(msg, flush=True)
        else:
            print(msg, flush=True)

    try:
        result = scanner_cls(username).scan()
        risk = result.get('risk', 'unknown')
        color = RISK_COLORS.get(risk, DIM)
        label_map = {
            'clean':      'ЧИСТО',
            'suspicious': 'ПОДОЗРИТЕЛЬНО',
            'danger':     'ОПАСНОСТЬ',
            'unknown':    'НЕИЗВЕСТНО',
        }
        _print(f'  {color}[{label_map.get(risk, risk.upper())}]{RESET} {label}')
        return result
    except Exception as e:
        _print(f'  {RED}[ОШИБКА]{RESET} {label}: {e}')
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
        server = http.server.HTTPServer(('127.0.0.1', port), SilentHandler)
    except OSError as e:
        print(f'\n{RED}[!] Не удалось запустить сервер на порту {port}: {e}{RESET}')
        print(f'    Открываю файл напрямую...')
        webbrowser.open(Path(output_path).as_uri())
        return

    url = f'http://localhost:{port}/{report_file}'
    print(f'\n{CYAN}{"─"*55}{RESET}')
    print(f'{BOLD}  Отчёт готов!{RESET}')
    print(f'{CYAN}{"─"*55}{RESET}')
    print(f'  Адрес: {BOLD}{url}{RESET}')
    print(f'  Файл:  {output_path}')
    print(f'\n  {DIM}Ctrl+C — остановить сервер{RESET}\n')

    threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f'\n{DIM}[*] Сервер остановлен.{RESET}')


def main():
    _enable_ansi()
    args = parse_args()

    if not is_admin():
        print(f'{YELLOW}[*] Запрос прав администратора (UAC)...{RESET}')
        if elevate_and_restart():
            # Успешно запустили повышенный процесс — выходим из текущего
            sys.exit(0)
        else:
            # Пользователь отклонил UAC — продолжаем без прав
            print(f'{YELLOW}[!] UAC отклонён. Часть проверок (Prefetch, BAM, память) будет ограничена.{RESET}\n')

    banner()

    print(f'{BOLD}  Пользователь:{RESET} {args.user}')
    print(f'{BOLD}  Время:{RESET} {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print(f'\n{CYAN}{"─"*55}{RESET}')
    print(f'  Запуск сканеров...\n')

    scanners = [
        ('processes',      'Сканер процессов',                   ProcessScanner),
        ('mods',           'Сканер модов (JAR)',                  ModScanner),
        ('native',         'Сканер native-библиотек (DLL)',       NativeScanner),
        ('network',        'Сканер сети',                         NetworkScanner),
        ('filesystem',     'Сканер файловой системы',             FilesystemScanner),
        ('integrity',      'Проверка целостности клиента',        IntegrityChecker),
        ('strings',        'Сканер строк',                        StringsScanner),
        ('artifacts',      'Forensic-артефакты (удалённые файлы)', ArtifactsScanner),
        ('shellbag',       'ShellBag (история папок)',             ShellBagScanner),
        ('executedprograms','ExecutedPrograms (история запусков)', ExecutedProgramsScanner),
    ]

    results = {}
    _print_lock = threading.Lock()

    def _run(key, label, cls):
        result = run_scanner(label, cls, args.user, _print_lock)
        return key, result

    # Параллельный запуск — все сканеры одновременно
    # (строки и диск C долгие, но не блокируют остальные)
    with ThreadPoolExecutor(max_workers=len(scanners)) as pool:
        futures = {pool.submit(_run, key, label, cls): key
                   for key, label, cls in scanners}
        for fut in as_completed(futures):
            key, result = fut.result()
            results[key] = result

    order = {'clean': 0, 'suspicious': 1, 'danger': 2, 'unknown': -1}
    overall = max(results.values(), key=lambda d: order.get(d.get('risk', 'unknown'), -1))
    overall_risk = overall.get('risk', 'unknown')
    risk_color = RISK_COLORS.get(overall_risk, DIM)
    risk_names = {
        'clean':      'ЧИСТО',
        'suspicious': 'ПОДОЗРИТЕЛЬНО',
        'danger':     'ОПАСНОСТЬ',
        'unknown':    'НЕИЗВЕСТНО',
    }

    print(f'\n{CYAN}{"─"*55}{RESET}')
    print(f'  Итоговый результат: {risk_color}{BOLD}{risk_names.get(overall_risk, overall_risk)}{RESET}')
    print(f'{CYAN}{"─"*55}{RESET}\n')

    print(f'  Генерация HTML-отчёта...', end='', flush=True)
    try:
        gen  = ReportGenerator(results, args.user)
        html = gen.generate()
        Path(args.output).write_text(html, encoding='utf-8')
        print(f'\r  {GREEN}[OK]{RESET} Отчёт сохранён: {args.output}')
    except Exception as e:
        print(f'\r  {RED}[!]{RESET} Ошибка генерации отчёта: {e}')
        sys.exit(1)

    if args.no_serve:
        webbrowser.open(Path(args.output).as_uri())
    else:
        serve_report(args.output, args.port)


if __name__ == '__main__':
    main()
