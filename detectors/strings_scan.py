import os
import re
import json
import ctypes
import ctypes.wintypes as wintypes
import zipfile
from pathlib import Path

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)

STRING_PATTERNS = [
    # Wurst
    (r'net\.wurstclient',           'Wurst Client',       'danger'),
    (r'WurstClient',                'Wurst Client',       'danger'),
    # LiquidBounce
    (r'net\.ccbluex\.liquidbounce', 'LiquidBounce',       'danger'),
    (r'LiquidBounce',               'LiquidBounce',       'danger'),
    # Meteor
    (r'meteordevelopment',          'Meteor Client',      'danger'),
    (r'MeteorClient',               'Meteor Client',      'danger'),
    # Impact
    (r'impact\.client',             'Impact Client',      'danger'),
    (r'ImpactClient',               'Impact Client',      'danger'),
    # Sigma
    (r'me\.sigma',                  'Sigma Client',       'danger'),
    (r'sigma\.client',              'Sigma Client',       'danger'),
    # Aristois
    (r'aristois',                   'Aristois Client',    'danger'),
    # Future
    (r'com\.future\.client',        'Future Client',      'danger'),
    # Vape
    (r'vape\.client',               'Vape Client',        'danger'),
    (r'VapeClient',                 'Vape Client',        'danger'),
    # Ghost
    (r'ghost\.client',              'Ghost Client',       'danger'),
    # Astolfo
    (r'astolfo\.client',            'Astolfo Client',     'danger'),
    # Novoline
    (r'novoline',                   'Novoline Client',    'danger'),
    # Killaura / modules
    (r'KillAura',                   'KillAura модуль',    'danger'),
    (r'AimAssist',                  'AimAssist модуль',   'danger'),
    (r'AutoClicker',                'AutoClicker модуль', 'danger'),
    (r'Scaffold',                   'Scaffold модуль',    'suspicious'),
    (r'ESP\.class',                 'ESP модуль',         'suspicious'),
    (r'XRay',                       'XRay модуль',        'danger'),
    (r'FreeCam',                    'FreeCam модуль',     'suspicious'),
    (r'NoFall',                     'NoFall модуль',      'suspicious'),
    (r'BunnyHop',                   'BunnyHop/Bhop',      'suspicious'),
    (r'SpeedHack',                  'Speed Hack',         'danger'),
    # Java Agent
    (r'java\.lang\.instrument',     'Java Instrumentation API', 'suspicious'),
    (r'ClassFileTransformer',       'Class Transformer (агент)', 'suspicious'),
    # Native injection
    (r'System\.loadLibrary',        'Загрузка native библиотеки', 'suspicious'),
    # Mixin
    (r'org\.spongepowered\.asm\.mixin', 'Mixin framework', 'info'),
    # ChatTriggers
    (r'chattriggers',               'ChatTriggers',       'suspicious'),
    # === ProstoTrainer manual: Process Hacker strings ===
    # Doomsday Client (уникальные строки)
    (r'SWqxNv',                     'Doomsday Client',    'danger'),
    (r'oNIkoasR',                   'Doomsday Client',    'danger'),
    # Vape V4
    (r'VAPE4DLL',                   'Vape V4',            'danger'),
    # Hitbox-читы (Forge)
    (r'ASM:\s',                     'Hitbox/Самопись',    'danger'),
    (r'bushroot',                   'Hitbox (bushroot)',   'danger'),
    (r'clowdy',                     'ClowdyClient',       'danger'),
    (r'Derick1337',                 'Hitbox (Derick1337)','danger'),
    (r'net\.minecraftforge\.ASMEventHandler\.31\.wait', 'Hitbox (Forge)', 'danger'),
    # Hitbox-читы (LabyMod/Vanilla)
    (r'reach:\s',                   'Vert Client',        'danger'),
    (r'baobab',                     'Hitbox (baobab)',    'danger'),
    (r"Az85'",                      'Knapa V4',           'danger'),
    (r'71L;',                       'Knapa V4',           'danger'),
    (r'hitbox:\s',                  'Vert Client',        'danger'),
    (r'Walvbt#',                    'Knapa V2',           'danger'),
    (r'#Hit\b',                     'Knapa V2',           'suspicious'),
    (r'okuma:',                     'Hitbox (okuma)',     'danger'),
    (r'chs/main',                   'Vertzah Client',     'suspicious'),
    (r'stubborn\.website',          'Cortex Client',      'danger'),
    # Самопись
    (r';\(Ljava/lang/Class<\*>;Ljava/lang/String;', 'Самопись (Self-write)', 'danger'),
    # FakeTapeMouse
    (r'Extension.*class',           'FakeTapeMouse',      'danger'),
    # Cortex (Prosto Launcher)
    (r'ICONCHECKBOX',               'Cortex (Prosto)',    'danger'),
    (r'EXITSAVE',                   'Cortex (Prosto)',    'suspicious'),
    (r'E\s+S\s+P',                  'Cortex ESP',        'danger'),
    # InvisibleHitbox
    (r'InvisibleHitbox',            'InvisibleHitbox',    'danger'),
    # NoRender
    (r'pastebin\.com.*jar|jar.*pastebin\.com', 'NoRender Lite', 'suspicious'),
    # Allatori обфускация
    (r'allatori',                   'Allatori обфускация','suspicious'),
    # Чит-сайты в памяти (браузер/лоадер)
    (r'cortexclient\.com',          'Cortex Client',      'danger'),
    (r'doomsdayclient\.com',        'Doomsday Client',    'danger'),
    (r'akrien\.wtf',                'Akrien Client',      'danger'),
    (r'ammit\.cc',                  'Ammit Client',       'danger'),
    (r'takker\.ru',                 'Takker',             'danger'),
    (r'dreampoolhack\.ru',          'DreamPool Hack',     'danger'),
    (r'nemezida\.cc',               'Nemezida',           'danger'),
    (r'neverlack\.in',              'NeverLack',          'danger'),
    (r'vk\.com/avaloneclient',      'Avalone Client',     'danger'),
    (r'vk\.com/norender',           'NoRender',           'danger'),
    (r'vk\.com/ammitclient',        'Ammit Client',       'danger'),
    (r'vk\.com/troxill',            'Troxill',            'danger'),
    # CIS читы
    (r'NURSULTAN|ru\.nursultan',    'Nursultan Client',   'danger'),
    (r'DEADCODE|me\.deadcode',      'DeadCode Client',    'danger'),
    (r'dauntiblyat',                'Cheat DLL',          'danger'),
    (r'clownware|clownclient',      'ClownWare',          'danger'),
    (r'me\.vertzah',                'Vertzah Client',     'danger'),
    (r'com\.cortex|cortex\.client', 'Cortex Client',      'danger'),
    (r'me\.doomsday|com\.doomsday', 'Doomsday Client',    'danger'),
]

# Windows API константы
PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT                = 0x1000
MEM_PRIVATE               = 0x20000   # anonymous (не file-backed) память
PAGE_NOACCESS             = 0x01
PAGE_GUARD                = 0x100
PAGE_EXECUTE              = 0x10
PAGE_EXECUTE_READ         = 0x20
PAGE_EXECUTE_READWRITE    = 0x40
PAGE_EXECUTE_WRITECOPY    = 0x80
MAX_SEGMENT_SIZE          = 4 * 1024 * 1024   # 4 МБ на регион

EXEC_PROTECTIONS = {
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
}


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       ctypes.c_size_t),
        ('AllocationBase',    ctypes.c_size_t),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize',        ctypes.c_size_t),
        ('State',             wintypes.DWORD),
        ('Protect',           wintypes.DWORD),
        ('Type',              wintypes.DWORD),
    ]


def _extract_strings(data: bytes, min_len: int = 6) -> str:
    """Извлечь ASCII-строки из бинарных данных (аналог утилиты strings)."""
    pattern = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')
    return '\n'.join(m.group().decode('ascii', errors='replace') for m in pattern.finditer(data))


def _read_process_memory(pid: int) -> bytes:
    """Читать всю доступную пользовательскую память процесса."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not handle:
        return b''

    chunks = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    user_space_limit = 0x7FFFFFFF0000

    try:
        while address < user_space_limit:
            ret = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not ret:
                break

            if (
                mbi.State == MEM_COMMIT
                and not (mbi.Protect & PAGE_NOACCESS)
                and not (mbi.Protect & PAGE_GUARD)
            ):
                size = min(mbi.RegionSize, MAX_SEGMENT_SIZE)
                buf = ctypes.create_string_buffer(size)
                read = ctypes.c_size_t(0)
                ok = kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(mbi.BaseAddress),
                    buf, size,
                    ctypes.byref(read),
                )
                if ok:
                    chunks.append(buf.raw[:read.value])

            next_addr = mbi.BaseAddress + mbi.RegionSize
            if next_addr <= address:
                break
            address = next_addr
    finally:
        kernel32.CloseHandle(handle)

    return b''.join(chunks)


def _read_anon_exec_regions(pid: int) -> list[tuple[str, bytes]]:
    """
    Читать anonymous executable регионы памяти (не привязанные к файлу).
    Именно в них оседают deleted-file читы и reflective-инжекции.
    Возвращает список (hex_addr, bytes).
    """
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not handle:
        return []

    results = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    user_space_limit = 0x7FFFFFFF0000

    try:
        while address < user_space_limit:
            ret = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not ret:
                break

            # Только anonymous (MEM_PRIVATE) executable страницы
            if (
                mbi.State == MEM_COMMIT
                and mbi.Type == MEM_PRIVATE
                and mbi.Protect in EXEC_PROTECTIONS
                and mbi.RegionSize >= 64 * 1024   # ≥ 64 КБ — исключаем крошечные JIT-блоки
            ):
                size = min(mbi.RegionSize, MAX_SEGMENT_SIZE)
                buf = ctypes.create_string_buffer(size)
                read = ctypes.c_size_t(0)
                ok = kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(mbi.BaseAddress),
                    buf, size,
                    ctypes.byref(read),
                )
                if ok and read.value:
                    results.append((hex(mbi.BaseAddress), buf.raw[:read.value]))

            next_addr = mbi.BaseAddress + mbi.RegionSize
            if next_addr <= address:
                break
            address = next_addr
    finally:
        kernel32.CloseHandle(handle)

    return results


class StringsScanner:
    """
    Сканирует строки в памяти Java-процессов и в файлах на диске.
    Использует Windows ReadProcessMemory API.
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

    def scan(self):
        self._scan_java_process_memory()
        self._scan_anon_exec_regions()   # ← deleted-file / memory-only читы
        self._scan_disk_files()
        return {
            'name': 'Сканер строк',
            'description': (
                'Поиск сигнатур читов в памяти Java-процессов (включая удалённые файлы) '
                'и файлах на диске'
            ),
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    # ─── Память процессов ─────────────────────────────────────────────────────

    def _scan_java_process_memory(self):
        if not PSUTIL_OK:
            self.findings.append({
                'level': 'info',
                'type': 'psutil_missing',
                'message': 'psutil не установлен — strings-сканирование памяти пропущено',
                'detail': 'pip install psutil',
            })
            return

        import psutil
        java_pids = []

        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                if 'java' not in (proc.info['name'] or '').lower():
                    continue
                win_user = (proc.info.get('username') or '')
                if '\\' in win_user:
                    win_user = win_user.split('\\')[-1]
                if self.username and self.username.lower() != win_user.lower():
                    continue
                java_pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not java_pids:
            self.findings.append({
                'level': 'info',
                'type': 'no_java_for_strings',
                'message': 'Java-процессов не найдено — strings-сканирование памяти пропущено',
                'detail': '',
            })
            return

        for pid in java_pids:
            self._scan_pid_memory(pid)

    def _scan_pid_memory(self, pid: int):
        try:
            raw = _read_process_memory(pid)
        except Exception:
            return
        if not raw:
            return
        text = _extract_strings(raw, min_len=8)
        found_signatures: set = set()
        self._match_patterns(str(pid), text, found_signatures, source='memory')

    # ─── Anonymous exec (deleted-file / reflective injection) ─────────────────

    def _scan_anon_exec_regions(self):
        """
        Явно сканирует anonymous executable страницы Java-процессов.
        Удалённые DLL/JAR, загруженные reflective-образом, не оставляют следов
        на диске, но их код остаётся в таких регионах.
        """
        if not PSUTIL_OK:
            return

        import psutil
        java_pids = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                if 'java' not in (proc.info['name'] or '').lower():
                    continue
                win_user = (proc.info.get('username') or '')
                if '\\' in win_user:
                    win_user = win_user.split('\\')[-1]
                if self.username and self.username.lower() != win_user.lower():
                    continue
                java_pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        for pid in java_pids:
            try:
                regions = _read_anon_exec_regions(pid)
            except Exception:
                continue
            found_signatures: set = set()
            for addr, data in regions:
                text = _extract_strings(data, min_len=6)
                source = f'anon-exec@{addr} (PID {pid})'
                self._match_patterns(str(pid), text, found_signatures, source=source)

    # ─── Файлы на диске ───────────────────────────────────────────────────────

    def _scan_disk_files(self):
        scan_roots = [self.appdata, self.localappdata]
        jar_files = []

        for root in scan_roots:
            if not root.exists():
                continue
            try:
                for jar in root.rglob('*.jar'):
                    if jar.stat().st_size < 50 * 1024 * 1024:
                        jar_files.append(jar)
            except (PermissionError, OSError):
                pass

        # Downloads — сканируем независимо от имени файла
        downloads = self.userprofile / 'Downloads'
        if downloads.exists():
            try:
                for f in downloads.iterdir():
                    if f.is_file() and f.suffix.lower() in ('.jar', '.dll'):
                        jar_files.append(f)
            except (PermissionError, OSError):
                pass

        # TEMP
        temp_dir = Path(os.environ.get('TEMP', ''))
        if temp_dir.exists():
            try:
                for f in temp_dir.iterdir():
                    if f.is_file() and f.suffix.lower() in ('.jar', '.dll', '.exe'):
                        jar_files.append(f)
            except (PermissionError, OSError):
                pass

        found_signatures: set = set()
        for target in jar_files:
            self._scan_file(target, found_signatures)

    def _scan_file(self, file_path: Path, found_signatures: set):
        try:
            # JAR → сканируем содержимое как ZIP
            if file_path.suffix.lower() == '.jar':
                try:
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        text_parts = []
                        for name in zf.namelist():
                            if name.endswith('.class') or name.endswith('.MF'):
                                try:
                                    data = zf.read(name)
                                    text_parts.append(_extract_strings(data, min_len=6))
                                except Exception:
                                    pass
                        text = '\n'.join(text_parts)
                except Exception:
                    raw = file_path.read_bytes()
                    text = _extract_strings(raw)
            else:
                raw = file_path.read_bytes()
                text = _extract_strings(raw)
        except (PermissionError, OSError):
            return

        self._match_patterns(str(file_path), text, found_signatures, source=str(file_path))

    def _match_patterns(self, location, text, found_signatures, source):
        for pattern, cheat_name, level in STRING_PATTERNS:
            sig_key = f'{cheat_name}:{source}'
            if sig_key in found_signatures:
                continue
            if re.search(pattern, text, re.IGNORECASE):
                found_signatures.add(sig_key)
                src_label = Path(source).name if (os.sep in source or '/' in source) else source
                self.findings.append({
                    'level': level,
                    'type': 'strings_signature_match',
                    'message': f'Сигнатура "{cheat_name}" найдена в {src_label}',
                    'detail': f'Паттерн: {pattern} | Источник: {source}',
                })
                self._set_risk(level)
