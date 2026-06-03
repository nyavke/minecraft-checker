"""
Forensic Artifacts Scanner — следы удалённых файлов на Windows.

Даже если читы удалены с диска, Windows хранит следы в:
  - Prefetch (C:\\Windows\\Prefetch\\*.pf)
  - $Recycle.Bin (удалено, но корзина не очищена)
  - BAM registry (Background Activity Monitor)
  - MuiCache registry (пути запущенных приложений)
  - AppCompatFlags registry
  - Recent files (%APPDATA%\\Microsoft\\Windows\\Recent\\)
  - История загрузок браузеров (Chrome, Edge, Firefox)
  - Папка Downloads
"""

import os
import re
import json
import shutil
import sqlite3
import struct
import ctypes
import ctypes.wintypes as wintypes
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

try:
    import winreg
    WINREG_OK = True
except ImportError:
    WINREG_OK = False

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)

# Объединённый список паттернов для поиска
ALL_CHEAT_PATTERNS = (
    SIGS['process_names']
    + SIGS['mod_name_patterns']
    + list(SIGS['java_package_signatures'].keys())
)


def _contains_cheat(text: str) -> tuple[bool, str]:
    """Проверить строку на совпадение с известными читами."""
    text_lower = text.lower()
    for pattern in ALL_CHEAT_PATTERNS:
        if pattern.lower() in text_lower:
            return True, pattern
    return False, ''


def _looks_random(name: str) -> bool:
    """
    Определить, похоже ли имя файла на случайно сгенерированное.
    jasdIJHDiFuasdiu — случайное; liquidbounce-7.4 — нет.
    """
    if len(name) < 8:
        return False
    # Много чередующихся регистров (camelCase-хаос) — признак рандома
    upper = sum(1 for c in name if c.isupper())
    lower = sum(1 for c in name if c.islower())
    total_alpha = upper + lower
    if total_alpha < 6:
        return False
    # Если доля заглавных от 20% до 80% И нет пробелов/дефисов — похоже на random
    ratio = upper / total_alpha
    has_separator = any(c in name for c in ('-', '_', '.', ' '))
    if 0.20 <= ratio <= 0.80 and not has_separator and len(name) >= 10:
        return True
    # Имя длиннее 14 символов без разделителей и без слов-читов — подозрительно
    if len(name) >= 14 and not has_separator:
        return True
    return False


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Извлечь ASCII и UTF-16LE строки из бинарных данных."""
    results = []
    # ASCII
    for m in re.finditer(rb'[ -~]{' + str(min_len).encode() + rb',}', data):
        results.append(m.group().decode('ascii', errors='replace'))
    # UTF-16 LE
    try:
        decoded = data.decode('utf-16-le', errors='replace')
        for m in re.finditer(r'[ -~Ѐ-ӿ]{' + str(min_len) + r',}', decoded):
            results.append(m.group())
    except Exception:
        pass
    return results


def _decompress_prefetch_mam(data: bytes) -> bytes | None:
    """
    Распаковать сжатый prefetch (Windows 8+, формат MAM).
    Использует ntdll.RtlDecompressBuffer с XPRESS Huffman.
    """
    if len(data) < 8 or data[:3] != b'MAM':
        return None
    uncompressed_size = struct.unpack('<I', data[4:8])[0]
    if uncompressed_size == 0 or uncompressed_size > 64 * 1024 * 1024:
        return None
    compressed = data[8:]
    out_buf = ctypes.create_string_buffer(uncompressed_size)
    final_sz = ctypes.c_ulong(0)
    ntdll = ctypes.windll.ntdll
    # 0x0104 = COMPRESSION_FORMAT_XPRESS_HUFF
    status = ntdll.RtlDecompressBuffer(
        0x0104, out_buf, uncompressed_size,
        compressed, len(compressed),
        ctypes.byref(final_sz),
    )
    if status == 0:   # STATUS_SUCCESS
        return out_buf.raw[:final_sz.value]
    return None


def _parse_recycle_bin_i_file(path: Path) -> str | None:
    """
    Разобрать $I-файл корзины и вернуть оригинальный путь.
    Формат v1 (Vista-7): header(8) + size(8) + time(8) + path(520 bytes UTF-16)
    Формат v2 (Win8+):   header(8) + size(8) + time(8) + len(4) + path(var UTF-16)
    """
    try:
        data = path.read_bytes()
        if len(data) < 24:
            return None
        version = struct.unpack('<Q', data[:8])[0]
        if version == 1:
            if len(data) < 544:
                return None
            raw_path = data[24:24 + 520]
            return raw_path.decode('utf-16-le', errors='replace').rstrip('\x00')
        elif version == 2:
            if len(data) < 28:
                return None
            path_len = struct.unpack('<I', data[24:28])[0]
            raw_path = data[28:28 + path_len * 2]
            return raw_path.decode('utf-16-le', errors='replace').rstrip('\x00')
    except (OSError, struct.error, UnicodeDecodeError):
        pass
    return None


def _rot13(s: str) -> str:
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - 97 + 13) % 26 + 97))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - 65 + 13) % 26 + 65))
        else:
            result.append(c)
    return ''.join(result)


def _filetime_to_dt(ft: int) -> str:
    """Конвертировать Windows FILETIME в читаемую дату."""
    try:
        ts = ft / 10_000_000 - 11_644_473_600
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=ts)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return '?'


# ─────────────────────────────────────────────────────────────────────────────

class ArtifactsScanner:
    """
    Ищет следы удалённых читов в forensic-артефактах Windows:
    Prefetch, $Recycle.Bin, BAM, MuiCache, AppCompatFlags, Recent.
    """

    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

        current = os.environ.get('USERNAME', '')
        if not username or username.lower() == current.lower():
            self.appdata      = Path(os.environ.get('APPDATA',      ''))
            self.localappdata = Path(os.environ.get('LOCALAPPDATA', ''))
            self.userprofile  = Path(os.environ.get('USERPROFILE',  ''))
        else:
            self.userprofile  = Path('C:/Users') / username
            self.appdata      = self.userprofile / 'AppData' / 'Roaming'
            self.localappdata = self.userprofile / 'AppData' / 'Local'

        # SID пользователя (нужен для BAM и $Recycle.Bin)
        self._sid = self._get_user_sid()

    def scan(self):
        self._scan_prefetch()
        self._scan_recycle_bin()
        self._scan_bam_registry()
        self._scan_muicache()
        self._scan_appcompat_flags()
        self._scan_recent_files()
        self._scan_userassist()
        self._scan_browser_downloads()   # ← история загрузок браузеров
        self._scan_downloads_folder()    # ← папка Downloads
        return {
            'name': 'Forensic-артефакты (удалённые файлы)',
            'description': (
                'Prefetch, $Recycle.Bin, BAM, MuiCache, AppCompatFlags, Recent, '
                'история загрузок браузеров — следы читов удалённых с диска'
            ),
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _get_user_sid(self) -> str:
        """Получить SID текущего пользователя через реестр."""
        if not WINREG_OK:
            return ''
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList',
            )
            idx = 0
            while True:
                try:
                    sid = winreg.EnumKey(key, idx)
                    idx += 1
                    try:
                        sub = winreg.OpenKey(key, sid)
                        profile_path, _ = winreg.QueryValueEx(sub, 'ProfileImagePath')
                        winreg.CloseKey(sub)
                        profile_name = Path(profile_path).name.lower()
                        if profile_name == self.username.lower():
                            winreg.CloseKey(key)
                            return sid
                    except (FileNotFoundError, OSError):
                        pass
                except OSError:
                    break
            winreg.CloseKey(key)
        except (OSError, FileNotFoundError):
            pass
        return ''

    # ─── Prefetch ─────────────────────────────────────────────────────────────

    def _scan_prefetch(self):
        """
        Prefetch-файлы хранят имя запущенного EXE и пути всех файлов,
        к которым он обращался. Java.exe-prefetch содержит пути к JAR-файлам.
        """
        prefetch_dir = Path('C:/Windows/Prefetch')
        if not prefetch_dir.exists():
            return

        try:
            pf_files = list(prefetch_dir.glob('*.pf'))
        except (PermissionError, OSError):
            self.findings.append({
                'level': 'info',
                'type': 'prefetch_access_denied',
                'message': 'Нет доступа к C:\\Windows\\Prefetch — запустите от имени администратора',
                'detail': '',
            })
            return

        for pf in pf_files:
            # 1. Проверяем имя файла (CHEATNAME-HASH.pf)
            exe_name = pf.stem.rsplit('-', 1)[0].lower()
            hit, pattern = _contains_cheat(exe_name)
            if hit:
                try:
                    mtime = datetime.fromtimestamp(pf.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                except OSError:
                    mtime = '?'
                self.findings.append({
                    'level': 'danger',
                    'type': 'prefetch_cheat_exe',
                    'message': f'Prefetch: {pf.stem}',
                    'detail': f'Последний запуск: {mtime} | Путь: {pf}',
                })
                self._set_risk('danger')
                continue

            # 2. Для java/javaw — читаем содержимое в поисках путей к JAR-читам
            if exe_name not in ('java', 'javaw', 'javaw.exe', 'java.exe'):
                continue

            self._scan_prefetch_content(pf)

    def _scan_prefetch_content(self, pf_path: Path):
        """Читать и декодировать prefetch, искать JAR-пути читов внутри."""
        try:
            raw = pf_path.read_bytes()
        except (PermissionError, OSError):
            return

        # Попытка распаковать сжатый prefetch (Windows 8+)
        if raw[:3] == b'MAM':
            decompressed = _decompress_prefetch_mam(raw)
            if decompressed:
                raw = decompressed

        strings = _extract_strings(raw, min_len=8)
        found = set()
        for s in strings:
            hit, pattern = _contains_cheat(s)
            if hit and pattern not in found:
                found.add(pattern)
                try:
                    mtime = datetime.fromtimestamp(
                        pf_path.stat().st_mtime
                    ).strftime('%Y-%m-%d %H:%M:%S')
                except OSError:
                    mtime = '?'
                self.findings.append({
                    'level': 'danger',
                    'type': 'prefetch_cheat_jar_path',
                    'message': f'Prefetch java.exe: найден путь к JAR-читу "{pattern}"',
                    'detail': (
                        f'Prefetch: {pf_path.name} | '
                        f'Последний запуск: {mtime} | '
                        f'Строка: {s[:200]}'
                    ),
                })
                self._set_risk('danger')

    # ─── $Recycle.Bin ─────────────────────────────────────────────────────────

    def _scan_recycle_bin(self):
        """
        Файлы удалены, но корзина не очищена.
        $I-файлы хранят оригинальный путь к удалённому файлу.
        """
        recycle_root = Path('C:/$Recycle.Bin')
        if not recycle_root.exists():
            return

        # Сканируем корзину текущего пользователя (по SID) и все доступные
        sid_dirs = []
        try:
            for entry in recycle_root.iterdir():
                if entry.is_dir():
                    if not self._sid or entry.name == self._sid:
                        sid_dirs.append(entry)
        except (PermissionError, OSError):
            return

        if not sid_dirs and self._sid:
            sid_dirs = [recycle_root / self._sid]

        for sid_dir in sid_dirs:
            if not sid_dir.exists():
                continue
            try:
                for i_file in sid_dir.glob('$I*'):
                    original_path = _parse_recycle_bin_i_file(i_file)
                    if not original_path:
                        continue
                    hit, pattern = _contains_cheat(original_path)
                    if hit:
                        # Получаем время удаления из $I файла
                        try:
                            data = i_file.read_bytes()
                            ft = struct.unpack('<Q', data[16:24])[0] if len(data) >= 24 else 0
                            del_time = _filetime_to_dt(ft) if ft else '?'
                        except (OSError, struct.error):
                            del_time = '?'

                        self.findings.append({
                            'level': 'danger',
                            'type': 'recycle_bin_cheat',
                            'message': f'$Recycle.Bin: удалённый чит-файл в корзине — "{pattern}"',
                            'detail': (
                                f'Оригинальный путь: {original_path}\n'
                                f'Удалён: {del_time}'
                            ),
                        })
                        self._set_risk('danger')
            except (PermissionError, OSError):
                pass

    # ─── BAM Registry ─────────────────────────────────────────────────────────

    def _scan_bam_registry(self):
        """
        Background Activity Monitor — реестр Windows трекает все запущенные
        программы с временной меткой. Требует администратора.
        """
        if not WINREG_OK:
            return

        bam_base = r'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
        try:
            bam_root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bam_base)
        except (OSError, FileNotFoundError):
            # Попробовать альтернативный путь (старые версии Windows)
            try:
                bam_root = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r'SYSTEM\CurrentControlSet\Services\bam\UserSettings',
                )
            except (OSError, FileNotFoundError):
                return

        # Итерируем по SID-подключам
        idx = 0
        while True:
            try:
                sid_key_name = winreg.EnumKey(bam_root, idx)
                idx += 1
            except OSError:
                break

            # Если знаем SID — проверяем только его, иначе все
            if self._sid and sid_key_name != self._sid:
                continue

            try:
                sid_key = winreg.OpenKey(bam_root, sid_key_name)
                val_idx = 0
                while True:
                    try:
                        name, data, vtype = winreg.EnumValue(sid_key, val_idx)
                        val_idx += 1
                        if not name or not isinstance(name, str):
                            continue
                        hit, pattern = _contains_cheat(name)
                        if hit:
                            # Время последнего запуска (FILETIME) в первых 8 байтах
                            run_time = '?'
                            if isinstance(data, bytes) and len(data) >= 8:
                                ft = struct.unpack('<Q', data[:8])[0]
                                run_time = _filetime_to_dt(ft)
                            self.findings.append({
                                'level': 'danger',
                                'type': 'bam_cheat_execution',
                                'message': f'BAM: чит запускался — "{pattern}"',
                                'detail': (
                                    f'Путь: {name}\n'
                                    f'Последний запуск: {run_time}'
                                ),
                            })
                            self._set_risk('danger')
                    except OSError:
                        break
                winreg.CloseKey(sid_key)
            except (OSError, FileNotFoundError):
                pass

        winreg.CloseKey(bam_root)

    # ─── MuiCache ─────────────────────────────────────────────────────────────

    def _scan_muicache(self):
        """
        MuiCache хранит пути к запускавшимся приложениям и их отображаемые имена.
        Даже после удаления программы запись остаётся.
        """
        if not WINREG_OK:
            return

        muicache_paths = [
            (winreg.HKEY_CURRENT_USER,
             r'Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'),
            (winreg.HKEY_CURRENT_USER,
             r'Software\Microsoft\Windows\ShellNoRoam\MUICache'),
        ]

        for hive, subkey in muicache_paths:
            try:
                key = winreg.OpenKey(hive, subkey)
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        idx += 1
                        hit, pattern = _contains_cheat(name)
                        if not hit:
                            hit, pattern = _contains_cheat(str(value))
                        if hit:
                            self.findings.append({
                                'level': 'danger',
                                'type': 'muicache_cheat',
                                'message': f'MuiCache: чит присутствовал в системе — "{pattern}"',
                                'detail': f'Путь/ключ: {name[:200]}\nЗначение: {str(value)[:200]}',
                            })
                            self._set_risk('danger')
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, FileNotFoundError):
                pass

    # ─── AppCompatFlags ───────────────────────────────────────────────────────

    def _scan_appcompat_flags(self):
        """
        AppCompatFlags\\Compatibility Assistant — Windows логирует запуск
        программ, которые требовали проверки совместимости.
        """
        if not WINREG_OK:
            return

        compat_keys = [
            (winreg.HKEY_CURRENT_USER,
             r'Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'),
            (winreg.HKEY_CURRENT_USER,
             r'Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted'),
        ]

        for hive, subkey in compat_keys:
            try:
                key = winreg.OpenKey(hive, subkey)
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        idx += 1
                        hit, pattern = _contains_cheat(name)
                        if hit:
                            self.findings.append({
                                'level': 'danger',
                                'type': 'appcompat_cheat',
                                'message': f'AppCompatFlags: чит запускался — "{pattern}"',
                                'detail': f'Путь: {name[:300]}',
                            })
                            self._set_risk('danger')
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, FileNotFoundError):
                pass

    # ─── Recent files ─────────────────────────────────────────────────────────

    def _scan_recent_files(self):
        """
        %APPDATA%\\Microsoft\\Windows\\Recent — ярлыки (.lnk) на недавно
        открытые файлы. Ярлык остаётся даже после удаления целевого файла.
        """
        recent_dir = self.appdata / 'Microsoft' / 'Windows' / 'Recent'
        if not recent_dir.exists():
            return

        try:
            for lnk in recent_dir.iterdir():
                if not lnk.is_file():
                    continue
                name_no_ext = lnk.stem.lower()
                hit, pattern = _contains_cheat(name_no_ext)
                if not hit:
                    # Попробуем прочитать содержимое .lnk как бинарник
                    try:
                        raw = lnk.read_bytes()
                        strings = _extract_strings(raw, min_len=8)
                        for s in strings:
                            hit, pattern = _contains_cheat(s)
                            if hit:
                                break
                    except (PermissionError, OSError):
                        pass
                if hit:
                    try:
                        mtime = datetime.fromtimestamp(
                            lnk.stat().st_mtime
                        ).strftime('%Y-%m-%d %H:%M:%S')
                    except OSError:
                        mtime = '?'
                    self.findings.append({
                        'level': 'danger',
                        'type': 'recent_file_cheat',
                        'message': f'Recent: ярлык на чит-файл — "{pattern}"',
                        'detail': f'Ярлык: {lnk.name} | Создан/изменён: {mtime}',
                    })
                    self._set_risk('danger')
        except (PermissionError, OSError):
            pass

    # ─── UserAssist ───────────────────────────────────────────────────────────

    def _scan_userassist(self):
        """
        UserAssist — реестр Explorer, хранит запущенные через GUI приложения.
        Пути закодированы ROT13.
        """
        if not WINREG_OK:
            return

        ua_base = r'Software\Microsoft\Windows NT\CurrentVersion\Explorer\UserAssist'
        try:
            ua_root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_base)
        except (OSError, FileNotFoundError):
            return

        guid_idx = 0
        while True:
            try:
                guid = winreg.EnumKey(ua_root, guid_idx)
                guid_idx += 1
            except OSError:
                break
            try:
                count_key = winreg.OpenKey(ua_root, guid + r'\Count')
                val_idx = 0
                while True:
                    try:
                        name, _, _ = winreg.EnumValue(count_key, val_idx)
                        val_idx += 1
                        decoded = _rot13(name)
                        hit, pattern = _contains_cheat(decoded)
                        if hit:
                            self.findings.append({
                                'level': 'danger',
                                'type': 'userassist_cheat',
                                'message': f'UserAssist: чит запускался через GUI — "{pattern}"',
                                'detail': f'Декодированный путь: {decoded[:300]}',
                            })
                            self._set_risk('danger')
                    except OSError:
                        break
                winreg.CloseKey(count_key)
            except (OSError, FileNotFoundError):
                pass

        winreg.CloseKey(ua_root)

    # ─── История загрузок браузеров ───────────────────────────────────────────

    def _scan_browser_downloads(self):
        """
        Читает историю загрузок Chrome, Edge (Chromium) и Firefox через SQLite.
        Даже если файл удалён после скачивания — запись в БД остаётся.
        """
        # Chromium-based (Chrome, Edge, Brave, Opera, Yandex, Vivaldi...)
        chromium_profiles = [
            self.localappdata / 'Google'          / 'Chrome'          / 'User Data',
            self.localappdata / 'Microsoft'       / 'Edge'            / 'User Data',
            self.localappdata / 'BraveSoftware'   / 'Brave-Browser'   / 'User Data',
            self.appdata      / 'Opera Software'  / 'Opera Stable',
            self.localappdata / 'Yandex'          / 'YandexBrowser'   / 'User Data',
            self.localappdata / 'Vivaldi'         / 'User Data',
        ]

        for browser_dir in chromium_profiles:
            if not browser_dir.exists():
                continue
            # Перебираем все профили (Default, Profile 1, Profile 2, ...)
            for profile in ['Default'] + [f'Profile {i}' for i in range(1, 6)]:
                history_db = browser_dir / profile / 'History'
                if history_db.exists():
                    self._query_chromium_downloads(history_db)

        # Firefox
        firefox_dir = self.appdata / 'Mozilla' / 'Firefox' / 'Profiles'
        if firefox_dir.exists():
            try:
                for profile_dir in firefox_dir.iterdir():
                    if profile_dir.is_dir():
                        places_db = profile_dir / 'places.sqlite'
                        if places_db.exists():
                            self._query_firefox_downloads(places_db)
            except (PermissionError, OSError):
                pass

    def _query_chromium_downloads(self, db_path: Path):
        """Запросить таблицу downloads из Chromium History SQLite."""
        tmp_db = None
        try:
            # Браузер может держать файл открытым — копируем во временный файл
            tmp_db = tempfile.mktemp(suffix='.db')
            shutil.copy2(str(db_path), tmp_db)

            conn = sqlite3.connect(tmp_db)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute(
                'SELECT target_path, tab_url, referrer, start_time '
                'FROM downloads ORDER BY start_time DESC LIMIT 2000'
            )
            rows = cur.fetchall()
            conn.close()

            browser_name = db_path.parts[-4] if len(db_path.parts) >= 4 else 'Browser'

            for row in rows:
                target  = row['target_path'] or ''
                url     = row['tab_url']     or ''
                referrer = row['referrer']   or ''

                # Проверяем путь к файлу, URL и referrer
                for text, label in ((target, 'путь'), (url, 'URL'), (referrer, 'referrer')):
                    hit, pattern = _contains_cheat(text)
                    if hit:
                        # Конвертируем Chrome-time (мкс с 1601-01-01) в дату
                        try:
                            st = row['start_time']
                            dt = _filetime_to_dt(st * 10) if st else '?'
                        except Exception:
                            dt = '?'

                        # Проверяем, существует ли файл сейчас
                        file_exists = Path(target).exists() if target else False
                        status = 'файл существует' if file_exists else 'файл УДАЛЁН'

                        self.findings.append({
                            'level': 'danger',
                            'type': 'browser_download_cheat',
                            'message': (
                                f'{browser_name}: скачивался чит "{pattern}" '
                                f'({status})'
                            ),
                            'detail': (
                                f'Файл: {target}\n'
                                f'URL: {url[:200]}\n'
                                f'Дата: {dt} | Статус: {status}'
                            ),
                        })
                        self._set_risk('danger')
                        break  # Не дублировать для одного скачивания

        except (sqlite3.Error, OSError, PermissionError, shutil.Error):
            pass
        finally:
            if tmp_db:
                try:
                    os.remove(tmp_db)
                except OSError:
                    pass

    def _query_firefox_downloads(self, db_path: Path):
        """Запросить историю загрузок из Firefox places.sqlite."""
        tmp_db = None
        try:
            tmp_db = tempfile.mktemp(suffix='.db')
            shutil.copy2(str(db_path), tmp_db)

            conn = sqlite3.connect(tmp_db)
            cur = conn.cursor()

            # moz_annos хранит download details; moz_places хранит URL
            cur.execute('''
                SELECT p.url, a.content, p.last_visit_date
                FROM moz_places p
                JOIN moz_annos a ON p.id = a.place_id
                WHERE a.anno_attribute_id IN (
                    SELECT id FROM moz_anno_attributes
                    WHERE name = "downloads/destinationFileURI"
                       OR name = "downloads/metaData"
                )
                ORDER BY p.last_visit_date DESC
                LIMIT 2000
            ''')
            rows = cur.fetchall()
            conn.close()

            for url, content, visit_date in rows:
                for text in (url or '', content or ''):
                    hit, pattern = _contains_cheat(text)
                    if hit:
                        try:
                            dt = _filetime_to_dt(visit_date) if visit_date else '?'
                        except Exception:
                            dt = '?'

                        # Извлечь путь из file:/// URI
                        file_path = ''
                        if content and content.startswith('file:///'):
                            file_path = content[8:].replace('/', '\\')
                        file_exists = Path(file_path).exists() if file_path else False
                        status = 'файл существует' if file_exists else 'файл УДАЛЁН'

                        self.findings.append({
                            'level': 'danger',
                            'type': 'browser_download_cheat',
                            'message': f'Firefox: скачивался чит "{pattern}" ({status})',
                            'detail': (
                                f'URL: {(url or "")[:200]}\n'
                                f'Файл: {file_path or content or "?"}\n'
                                f'Дата: {dt} | Статус: {status}'
                            ),
                        })
                        self._set_risk('danger')
                        break

        except (sqlite3.Error, OSError, PermissionError, shutil.Error):
            pass
        finally:
            if tmp_db:
                try:
                    os.remove(tmp_db)
                except OSError:
                    pass

    # ─── Папка Downloads ──────────────────────────────────────────────────────

    def _scan_downloads_folder(self):
        """
        Сканирует Downloads на JAR-файлы читов.
        Проверяет ТРИ уровня: имя файла → содержимое JAR → Zone.Identifier ADS.
        Файл с рандомным именем (jasdIJHDiFuasdiu.jar) детектируется по классам внутри.
        """
        import zipfile as _zipfile

        downloads = self.userprofile / 'Downloads'
        if not downloads.exists():
            return

        try:
            entries = list(downloads.iterdir())
        except (PermissionError, OSError):
            return

        for entry in entries:
            if not entry.is_file():
                continue

            detected = False

            # ── 1. Проверка имени ─────────────────────────────────────────────
            name_lower = entry.name.lower()
            hit, pattern = _contains_cheat(name_lower)
            if hit:
                self.findings.append({
                    'level': 'danger',
                    'type': 'downloads_cheat_name',
                    'message': f'Downloads: чит-файл (имя) — "{pattern}" → {entry.name}',
                    'detail': str(entry),
                })
                self._set_risk('danger')
                detected = True

            # ── 2. Zone.Identifier ADS (URL источника) ────────────────────────
            if not detected:
                zone_path = str(entry) + ':Zone.Identifier'
                try:
                    with open(zone_path, 'r', encoding='utf-8', errors='replace') as zf:
                        zone_content = zf.read()
                    hit, pattern = _contains_cheat(zone_content)
                    if hit:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'downloads_cheat_zone',
                            'message': (
                                f'Downloads: файл скачан с сайта чита '
                                f'"{pattern}" — {entry.name}'
                            ),
                            'detail': zone_content[:400],
                        })
                        self._set_risk('danger')
                        detected = True
                except (OSError, PermissionError):
                    pass

            # ── 3. Содержимое JAR (работает при любом имени файла) ────────────
            if entry.suffix.lower() == '.jar':
                # Рандомное имя само по себе — уже подозрительно для JAR в Downloads
                if not detected and _looks_random(entry.stem):
                    self.findings.append({
                        'level': 'suspicious',
                        'type': 'downloads_jar_random_name',
                        'message': (
                            f'Downloads: JAR со случайным именем — {entry.name}'
                        ),
                        'detail': (
                            f'Путь: {entry}\n'
                            f'Размер: {entry.stat().st_size} байт\n'
                            f'Имя выглядит случайно сгенерированным — '
                            f'типичная техника сокрытия читов'
                        ),
                    })
                    self._set_risk('suspicious')
                    detected = True
                self._inspect_jar_content(entry, detected)

    def _inspect_jar_content(self, jar_path: Path, already_detected: bool):
        """
        Смотрит внутрь JAR независимо от имени файла.
        Ловит читы переименованные в случайное имя (jasdIJHDiFuasdiu.jar).
        """
        import zipfile as _zipfile

        try:
            with _zipfile.ZipFile(jar_path, 'r') as zf:
                names = zf.namelist()
                class_files = [n for n in names if n.endswith('.class')]

                # ─ a) Проверка пакетов классов по сигнатурам читов ────────────
                for class_file in class_files:
                    class_path = class_file.replace('/', '.').removesuffix('.class')
                    for pkg_sig, cheat_name in SIGS['java_package_signatures'].items():
                        if class_path.startswith(pkg_sig):
                            self.findings.append({
                                'level': 'danger',
                                'type': 'downloads_jar_cheat_class',
                                'message': (
                                    f'Downloads JAR: обнаружены классы {cheat_name} '
                                    f'в "{jar_path.name}"'
                                ),
                                'detail': (
                                    f'Класс: {class_path}\n'
                                    f'Сигнатура: {pkg_sig}\n'
                                    f'Путь: {jar_path}'
                                ),
                            })
                            self._set_risk('danger')
                            return

                # ─ b) Проверка MANIFEST.MF ────────────────────────────────────
                if 'META-INF/MANIFEST.MF' in names:
                    manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
                    hit, pattern = _contains_cheat(manifest)
                    if hit:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'downloads_jar_cheat_manifest',
                            'message': (
                                f'Downloads JAR: чит в MANIFEST.MF '
                                f'"{jar_path.name}" — "{pattern}"'
                            ),
                            'detail': f'Путь: {jar_path}\n{manifest[:300]}',
                        })
                        self._set_risk('danger')
                        return

                # ─ c) Обфускация + рандомное имя = подозрительно ──────────────
                if not already_detected and class_files:
                    short_names = [
                        Path(c).stem for c in class_files
                        if len(Path(c).stem) <= 2 and Path(c).stem.isalpha()
                    ]
                    ratio = len(short_names) / len(class_files) if class_files else 0
                    name_is_random = _looks_random(jar_path.stem)

                    if name_is_random or (ratio > 0.5 and len(class_files) > 10):
                        reason_parts = []
                        if name_is_random:
                            reason_parts.append('случайное имя файла')
                        if ratio > 0.5 and len(class_files) > 10:
                            reason_parts.append(
                                f'обфускация {int(ratio*100)}% коротких имён классов'
                            )
                        self.findings.append({
                            'level': 'suspicious',
                            'type': 'downloads_jar_suspicious',
                            'message': (
                                f'Downloads: подозрительный JAR — {jar_path.name} '
                                f'({", ".join(reason_parts)})'
                            ),
                            'detail': (
                                f'Путь: {jar_path}\n'
                                f'Классов: {len(class_files)}, '
                                f'коротких имён: {len(short_names)}\n'
                                f'Проверьте файл вручную'
                            ),
                        })
                        self._set_risk('suspicious')

        except (_zipfile.BadZipFile, PermissionError, OSError):
            pass