"""
ShellBag Scanner — мануал тема 7 | ShellBag.

ShellBag хранит историю посещённых папок в реестре Windows,
включая УДАЛЁННЫЕ папки. Если игрок открывал папку чита —
след останется даже после удаления всего.
"""

import re
import json
from pathlib import Path

try:
    import winreg
    WINREG_OK = True
except ImportError:
    WINREG_OK = False

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)

ALL_CHEAT_PATTERNS = (
    SIGS['mod_name_patterns']
    + SIGS['process_names']
    + list(SIGS['java_package_signatures'].keys())
)

SHELLBAG_KEYS = [
    r'Software\Microsoft\Windows\Shell\BagMRU',
    r'Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU',
]


def _extract_strings(data: bytes, min_len: int = 5) -> str:
    """Извлечь ASCII и UTF-16LE строки из бинарных данных ShellBag."""
    parts = []
    for m in re.finditer(rb'[ -~]{' + str(min_len).encode() + rb',}', data):
        parts.append(m.group().decode('ascii', errors='replace'))
    try:
        decoded = data.decode('utf-16-le', errors='replace')
        for m in re.finditer(r'[\x20-\x7EЀ-ӿ]{' + str(min_len) + r',}', decoded):
            parts.append(m.group())
    except Exception:
        pass
    return '\n'.join(parts)


def _contains_cheat(text: str):
    tl = text.lower()
    for p in ALL_CHEAT_PATTERNS:
        if p.lower() in tl:
            return True, p
    return False, ''


def _walk_bagmru(hive, subkey: str, depth: int = 0) -> list[str]:
    """Рекурсивно читать BagMRU и извлекать строки из бинарных значений."""
    if depth > 8:
        return []
    results = []
    try:
        key = winreg.OpenKey(hive, subkey)
        idx = 0
        while True:
            try:
                name, data, vtype = winreg.EnumValue(key, idx)
                idx += 1
                if isinstance(data, bytes) and len(data) > 4:
                    results.append(_extract_strings(data))
            except OSError:
                break
        # Рекурсия по подключам (числовые — это дочерние элементы BagMRU)
        sub_idx = 0
        while True:
            try:
                sub_name = winreg.EnumKey(key, sub_idx)
                sub_idx += 1
                if sub_name.isdigit():
                    results.extend(_walk_bagmru(hive, subkey + '\\' + sub_name, depth + 1))
            except OSError:
                break
        winreg.CloseKey(key)
    except (OSError, FileNotFoundError):
        pass
    return results


class ShellBagScanner:
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        if not WINREG_OK:
            return {
                'name': 'ShellBag (история папок)',
                'description': 'Недоступно — winreg не найден',
                'findings': [],
                'risk': 'clean',
            }
        self._scan_shellbags()
        return {
            'name': 'ShellBag (история папок)',
            'description': (
                'История посещённых папок из реестра — '
                'обнаруживает удалённые чит-клиенты'
            ),
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _scan_shellbags(self):
        seen = set()
        for subkey in SHELLBAG_KEYS:
            strings_list = _walk_bagmru(winreg.HKEY_CURRENT_USER, subkey)
            for text in strings_list:
                hit, pattern = _contains_cheat(text)
                if hit and pattern not in seen:
                    seen.add(pattern)
                    # Попытаемся найти читаемый путь в тексте
                    readable = next(
                        (line for line in text.splitlines()
                         if len(line) > 4 and pattern.lower() in line.lower()),
                        text[:100]
                    )
                    self.findings.append({
                        'level': 'danger',
                        'type': 'shellbag_cheat_folder',
                        'message': (
                            f'ShellBag: папка чита "{pattern}" посещалась '
                            f'(файлы могут быть удалены)'
                        ),
                        'detail': readable.strip(),
                    })
                    self._set_risk('danger')
