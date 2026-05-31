import os
import re
import json
import subprocess
from pathlib import Path

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)

# Строковые сигнатуры читов — ищутся в памяти процессов и бинарниках
STRING_PATTERNS = [
    # Wurst
    (r'net\.wurstclient',          'Wurst Client',       'danger'),
    (r'WurstClient',               'Wurst Client',       'danger'),
    # LiquidBounce
    (r'net\.ccbluex\.liquidbounce','LiquidBounce',       'danger'),
    (r'LiquidBounce',              'LiquidBounce',       'danger'),
    # Meteor
    (r'meteordevelopment',         'Meteor Client',      'danger'),
    (r'MeteorClient',              'Meteor Client',      'danger'),
    # Impact
    (r'impact\.client',            'Impact Client',      'danger'),
    (r'ImpactClient',              'Impact Client',      'danger'),
    # Sigma
    (r'me\.sigma',                 'Sigma Client',       'danger'),
    (r'sigma\.client',             'Sigma Client',       'danger'),
    # Aristois
    (r'aristois',                  'Aristois Client',    'danger'),
    # Future
    (r'com\.future\.client',       'Future Client',      'danger'),
    # Vape
    (r'vape\.client',              'Vape Client',        'danger'),
    (r'VapeClient',                'Vape Client',        'danger'),
    # Ghost
    (r'ghost\.client',             'Ghost Client',       'danger'),
    # Astolfo
    (r'astolfo\.client',           'Astolfo Client',     'danger'),
    # Novoline
    (r'novoline',                  'Novoline Client',    'danger'),
    # Killaura / AimAssist
    (r'KillAura',                  'KillAura модуль',    'danger'),
    (r'AimAssist',                 'AimAssist модуль',   'danger'),
    (r'AutoClicker',               'AutoClicker модуль', 'danger'),
    (r'Scaffold',                  'Scaffold модуль',    'suspicious'),
    (r'ESP\.class',                'ESP модуль',         'suspicious'),
    (r'XRay',                      'XRay модуль',        'danger'),
    (r'FreeCam',                   'FreeCam модуль',     'suspicious'),
    (r'NoFall',                    'NoFall модуль',      'suspicious'),
    (r'BunnyHop',                  'BunnyHop/Bhop',      'suspicious'),
    (r'SpeedHack',                 'Speed Hack',         'danger'),
    # Java Agent / Instrumentation
    (r'java\.lang\.instrument',    'Java Instrumentation API', 'suspicious'),
    (r'ClassFileTransformer',      'Class Transformer (агент)', 'suspicious'),
    (r'Instrumentation',           'Java Instrumentation',     'suspicious'),
    # Native injection
    (r'System\.loadLibrary',       'Загрузка native библиотеки', 'suspicious'),
    (r'LD_PRELOAD',                'LD_PRELOAD строка',   'danger'),
    # Mixin (может быть легитимным, но характерен для чит-клиентов)
    (r'org\.spongepowered\.asm\.mixin', 'Mixin framework', 'info'),
    # ChatTriggers (может быть использован для читов)
    (r'chattriggers',              'ChatTriggers',       'suspicious'),
]

# Размер блока при чтении /proc/[pid]/mem (64 КБ)
MEM_BLOCK_SIZE = 65536
# Максимум байт на сегмент памяти для чтения (4 МБ — баланс скорость/охват)
MAX_SEGMENT_SIZE = 4 * 1024 * 1024


class StringsScanner:
    """
    Сканирует строки в памяти Java-процессов и в файлах на диске.
    Аналог Ocean SS Tool: проверяет бинарные данные на сигнатуры читов.
    """
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'
        self._strings_bin = self._find_strings_binary()

    def scan(self):
        self._scan_java_process_memory()
        self._scan_disk_files()
        return {
            'name': 'Сканер строк (strings)',
            'description': 'Поиск сигнатур читов в памяти Java-процессов и файлах на диске (как Ocean SS)',
            'findings': self.findings,
            'risk': self.risk
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _find_strings_binary(self):
        for candidate in ('strings', '/usr/bin/strings', '/usr/local/bin/strings'):
            try:
                result = subprocess.run([candidate, '--version'],
                                        capture_output=True, timeout=3)
                return candidate
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None

    # ─── Сканирование памяти через /proc/[pid]/mem ────────────────────────────

    def _scan_java_process_memory(self):
        try:
            import pwd
            target_uid = pwd.getpwnam(self.username).pw_uid
        except (KeyError, ImportError):
            target_uid = None

        proc_path = Path('/proc')
        java_pids = []

        for pid_dir in proc_path.iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                cmdline_raw = (pid_dir / 'cmdline').read_bytes()
                cmdline = cmdline_raw.replace(b'\x00', b' ').decode('utf-8', errors='replace')
                if 'java' not in cmdline.lower():
                    continue

                if target_uid is not None:
                    uid_line = next(
                        (l for l in (pid_dir / 'status').read_text().splitlines()
                         if l.startswith('Uid:')), None
                    )
                    if uid_line:
                        uid = int(uid_line.split()[1])
                        if uid != target_uid:
                            continue

                java_pids.append(pid_dir.name)
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue

        if not java_pids:
            self.findings.append({
                'level': 'info',
                'type': 'no_java_for_strings',
                'message': 'Java-процессов не найдено — strings-сканирование памяти пропущено',
                'detail': ''
            })
            return

        for pid in java_pids:
            self._scan_pid_memory(pid)
            self._scan_pid_via_strings_tool(pid)

    def _scan_pid_memory(self, pid):
        maps_path  = Path(f'/proc/{pid}/maps')
        mem_path   = Path(f'/proc/{pid}/mem')

        if not maps_path.exists() or not mem_path.exists():
            return

        try:
            maps = maps_path.read_text()
        except (PermissionError, OSError):
            return

        found_signatures = set()

        try:
            with open(mem_path, 'rb') as mem_file:
                for line in maps.splitlines():
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    # Только readable сегменты heap/stack/анонимные
                    perms = parts[1]
                    if 'r' not in perms:
                        continue
                    region_name = parts[-1] if len(parts) >= 6 else ''
                    # Читаем только heap, stack и анонимные регионы
                    if region_name.startswith('/') and not region_name.startswith('/tmp'):
                        continue

                    try:
                        start_addr, end_addr = (int(x, 16) for x in parts[0].split('-'))
                    except ValueError:
                        continue

                    size = end_addr - start_addr
                    if size > MAX_SEGMENT_SIZE:
                        size = MAX_SEGMENT_SIZE

                    try:
                        mem_file.seek(start_addr)
                        data = mem_file.read(size)
                    except (OSError, OverflowError):
                        continue

                    text = data.decode('utf-8', errors='replace')
                    self._match_patterns(pid, text, found_signatures, source='memory')

        except (PermissionError, OSError):
            # Нет прав — пропускаем чтение памяти напрямую
            pass

    def _scan_pid_via_strings_tool(self, pid):
        """Запускает `strings /proc/[pid]/exe` — быстро, не требует чтения памяти."""
        if not self._strings_bin:
            return

        exe_path = f'/proc/{pid}/exe'
        if not os.path.exists(exe_path):
            return

        try:
            result = subprocess.run(
                [self._strings_bin, '-n', '8', exe_path],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout
        except (subprocess.TimeoutExpired, OSError, PermissionError):
            return

        found_signatures = set()
        self._match_patterns(pid, output, found_signatures, source='exe-strings')

    # ─── Сканирование файлов на диске ────────────────────────────────────────

    def _scan_disk_files(self):
        if not self._strings_bin:
            self.findings.append({
                'level': 'info',
                'type': 'strings_not_found',
                'message': '`strings` утилита не найдена — установите binutils для полного сканирования',
                'detail': 'pacman -S binutils  /  apt install binutils'
            })
            return

        home = Path(f'/home/{self.username}')
        scan_targets = []

        # JAR-файлы Minecraft
        for pattern in ('**/*.jar', '**/*.so'):
            try:
                for f in home.glob(pattern):
                    if f.stat().st_size < 50 * 1024 * 1024:  # пропускаем файлы > 50 МБ
                        scan_targets.append(f)
            except (PermissionError, OSError):
                pass

        # Файлы в /tmp и /dev/shm
        for tmp_dir in (Path('/tmp'), Path('/dev/shm')):
            if tmp_dir.exists():
                try:
                    for f in tmp_dir.iterdir():
                        if f.is_file():
                            scan_targets.append(f)
                except (PermissionError, OSError):
                    pass

        found_signatures: set = set()
        for target in scan_targets:
            self._strings_scan_file(target, found_signatures)

    def _strings_scan_file(self, file_path, found_signatures):
        try:
            result = subprocess.run(
                [self._strings_bin, '-n', '8', str(file_path)],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout
        except (subprocess.TimeoutExpired, OSError, PermissionError):
            return

        self._match_patterns(str(file_path), output, found_signatures, source=str(file_path))

    def _match_patterns(self, location, text, found_signatures, source):
        for pattern, cheat_name, level in STRING_PATTERNS:
            sig_key = f'{cheat_name}:{source}'
            if sig_key in found_signatures:
                continue
            if re.search(pattern, text, re.IGNORECASE):
                found_signatures.add(sig_key)
                self.findings.append({
                    'level': level,
                    'type': 'strings_signature_match',
                    'message': f'Сигнатура "{cheat_name}" найдена в {Path(source).name if "/" in source else source}',
                    'detail': f'Паттерн: {pattern} | Источник: {source} | PID/Файл: {location}'
                })
                self._set_risk(level)
