"""
ExecutedPrograms Scanner — мануал тема 12 | ExecutedProgramsList.

Читает ShimCache (AppCompatCache) из реестра — Windows записывает
туда все когда-либо запущенные EXE с путями. Работает даже если
файл удалён.

Также проверяет Prefetch-файлы по именам (без парсинга содержимого).
"""

import re
import struct
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta  # noqa: F401 — timedelta used in _filetime_to_str

try:
    import winreg
    WINREG_OK = True
except ImportError:
    WINREG_OK = False

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json', encoding='utf-8') as f:
    SIGS = json.load(f)

ALL_PATTERNS = SIGS['mod_name_patterns'] + SIGS['process_names']


def _contains_cheat(text: str):
    tl = text.lower()
    for p in ALL_PATTERNS:
        if p.lower() in tl:
            return True, p
    return False, ''


def _extract_paths_from_shimcache(data: bytes) -> list[str]:
    """
    Извлечь пути EXE из бинарного блока ShimCache.
    Windows 10/11: сигнатура 0x30/0x34 в начале.
    Простой подход — извлечь UTF-16LE строки длиннее 5 символов.
    """
    paths = []
    i = 0
    while i < len(data) - 1:
        word = int.from_bytes(data[i:i+2], 'little')
        if 0x20 <= word <= 0x7E:
            start = i
            chars = []
            while i < len(data) - 1:
                w = int.from_bytes(data[i:i+2], 'little')
                if 0x20 <= w <= 0x7E or w in (0x5C, 0x3A, 0x2E):  # \ : .
                    chars.append(chr(w))
                    i += 2
                else:
                    break
            if len(chars) >= 8:
                s = ''.join(chars)
                if '\\' in s or ':' in s:
                    paths.append(s)
        else:
            i += 2
    return paths


def _filetime_to_str(ft: int) -> str:
    try:
        ts = ft / 10_000_000 - 11_644_473_600
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=ts)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return '?'


class ExecutedProgramsScanner:
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        self._scan_shimcache()
        self._scan_prefetch_names()
        return {
            'name': 'ExecutedPrograms (история запусков)',
            'description': (
                'ShimCache (AppCompatCache) + Prefetch — '
                'все когда-либо запущенные EXE, включая удалённые'
            ),
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _scan_shimcache(self):
        """
        AppCompatCache — бинарный blob в реестре со всеми запущенными EXE.
        Не очищается при удалении файлов.
        """
        if not WINREG_OK:
            return
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache',
            )
            data, _ = winreg.QueryValueEx(key, 'AppCompatCache')
            winreg.CloseKey(key)
        except (OSError, FileNotFoundError):
            self.findings.append({
                'level': 'info',
                'type': 'shimcache_no_access',
                'message': 'ShimCache недоступен — запустите от имени администратора',
                'detail': '',
            })
            return

        if not isinstance(data, bytes):
            return

        paths = _extract_paths_from_shimcache(data)
        seen = set()
        for path in paths:
            hit, pattern = _contains_cheat(path)
            if hit and pattern not in seen:
                seen.add(pattern)
                self.findings.append({
                    'level': 'danger',
                    'type': 'shimcache_cheat_exe',
                    'message': f'ShimCache: чит запускался — "{pattern}"',
                    'detail': path,
                })
                self._set_risk('danger')

    def _scan_prefetch_names(self):
        """
        Prefetch: имена файлов = EXENAME-HASH.pf.
        Имя раскрывает запущенный EXE без парсинга бинарного содержимого.
        Требует администратора для доступа к C:\\Windows\\Prefetch.
        """
        prefetch_dir = Path('C:/Windows/Prefetch')
        if not prefetch_dir.exists():
            return
        try:
            for pf in prefetch_dir.glob('*.pf'):
                exe_name = pf.stem.rsplit('-', 1)[0].lower()
                hit, pattern = _contains_cheat(exe_name)
                if hit:
                    try:
                        mtime = datetime.fromtimestamp(
                            pf.stat().st_mtime
                        ).strftime('%Y-%m-%d %H:%M:%S')
                    except OSError:
                        mtime = '?'
                    self.findings.append({
                        'level': 'danger',
                        'type': 'prefetch_cheat_exe',
                        'message': f'Prefetch: {pf.stem}',
                        'detail': f'Последний запуск: {mtime} | {pf}',
                    })
                    self._set_risk('danger')
        except (PermissionError, OSError):
            self.findings.append({
                'level': 'info',
                'type': 'prefetch_no_access',
                'message': 'C:\\Windows\\Prefetch недоступен — нужны права администратора',
                'detail': '',
            })
