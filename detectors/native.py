import os
import json
import ctypes
import ctypes.wintypes as wintypes
from pathlib import Path

try:
    import winreg
    WINREG_OK = True
except ImportError:
    WINREG_OK = False

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json', encoding='utf-8') as f:
    SIGS = json.load(f)

SUSPICIOUS_DLL_KEYWORDS = [
    'inject', 'hook', 'hack', 'cheat', 'bypass', 'loader',
    'preload', 'patch', 'payload', 'killa', 'aura', 'aimbot',
    'cortex', 'vape4', 'nursultan', 'neverhook', 'gishcode',
    'troxill', 'vertzah', 'airatium', 'fmt32', 'fmt64',
    'easycheat', 'topkaautobuy', 'lunaroptimize', 'dauntiblyat',
]

# ─── Windows API ──────────────────────────────────────────────────────────────

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
TH32CS_SNAPMODULE         = 0x00000008
TH32CS_SNAPMODULE32       = 0x00000010
MAX_PATH                  = 260
MEM_COMMIT                = 0x1000
MEM_PRIVATE               = 0x20000   # anonymous (not file-backed) memory
PAGE_NOACCESS             = 0x01
PAGE_GUARD                = 0x100
PAGE_EXECUTE              = 0x10
PAGE_EXECUTE_READ         = 0x20
PAGE_EXECUTE_READWRITE    = 0x40
PAGE_EXECUTE_WRITECOPY    = 0x80

EXEC_PROTECTIONS = {
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
}

# Minimum size of an anonymous exec region considered suspicious.
# JVM JIT creates many small regions; a large single block is a sign of injection.
ANON_EXEC_SUSPICIOUS_SIZE = 512 * 1024   # 512 KB


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize',       wintypes.DWORD),
        ('th32ModuleID', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('GlblcntUsage', wintypes.DWORD),
        ('ProccntUsage', wintypes.DWORD),
        ('modBaseAddr',  ctypes.POINTER(ctypes.c_byte)),
        ('modBaseSize',  wintypes.DWORD),
        ('hModule',      wintypes.HMODULE),
        ('szModule',     ctypes.c_wchar * 256),
        ('szExePath',    ctypes.c_wchar * MAX_PATH),
    ]


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


def _get_loaded_modules(pid):
    """Get all modules of a process via CreateToolhelp32Snapshot."""
    kernel32 = ctypes.windll.kernel32
    snap = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
    )
    if snap == ctypes.c_void_p(-1).value:
        return []

    modules = []
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(MODULEENTRY32W)

    try:
        if kernel32.Module32FirstW(snap, ctypes.byref(me)):
            while True:
                modules.append(me.szExePath)
                if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                    break
    finally:
        kernel32.CloseHandle(snap)

    return modules


def _enum_exec_memory(pid):
    """Return a list of anonymous executable memory regions for the process."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not handle:
        return []

    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    user_limit = 0x7FFFFFFF0000

    try:
        while address < user_limit:
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
                and mbi.Type == MEM_PRIVATE
                and mbi.Protect in EXEC_PROTECTIONS
                and mbi.RegionSize >= ANON_EXEC_SUSPICIOUS_SIZE
            ):
                regions.append({
                    'base':    hex(mbi.BaseAddress),
                    'size_kb': mbi.RegionSize // 1024,
                    'protect': hex(mbi.Protect),
                })

            next_addr = mbi.BaseAddress + mbi.RegionSize
            if next_addr <= address:
                break
            address = next_addr
    finally:
        kernel32.CloseHandle(handle)

    return regions


# ─── Scanner ──────────────────────────────────────────────────────────────────


class NativeScanner:
    """
    Windows native level:
    - Phantom modules (loaded into memory, file deleted from disk)
    - Anonymous executable memory (reflective injection / deleted-file cheats)
    - AppInit_DLLs, IFEO
    - Suspicious files in TEMP and AppData
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
        self._check_appinit_dlls()
        self._check_ifeo_hijacking()
        self._scan_temp_for_executables()
        self._scan_appdata_for_suspicious_dlls()
        if PSUTIL_OK:
            self._check_loaded_dlls_in_java()
            self._check_phantom_modules()        # ← удалённые файлы, всё ещё в памяти
            self._check_anon_exec_regions()      # ← reflective/memory-only injection
        return {
            'name': 'Native Library Scanner (DLL)',
            'description': (
                'AppInit_DLLs, IFEO, phantom modules (deleted files in memory), '
                'anonymous exec pages, suspicious DLL/JAR in TEMP and AppData'
            ),
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    # ─── Phantom modules ──────────────────────────────────────────────────────

    def _check_phantom_modules(self):
        """
        Finds DLLs that are loaded into a Java process but already deleted from disk.
        Typical cheat technique: load DLL → delete file → no traces on disk.
        """
        import psutil
        for proc in self._iter_java_procs():
            pid = proc.info['pid']
            try:
                modules = _get_loaded_modules(pid)
            except Exception:
                continue

            for path in modules:
                if not path:
                    continue
                # Exclude auxiliary pseudo-paths (memory-mapped sections without a file)
                if path.startswith('\\') and not path.startswith('\\\\?\\'):
                    continue
                p = Path(path)
                try:
                    exists = p.exists()
                except (OSError, ValueError):
                    continue
                if not exists:
                    self.findings.append({
                        'level': 'danger',
                        'type': 'phantom_module',
                        'message': (
                            f'Phantom module: file deleted from disk but still in JVM memory '
                            f'(PID {pid})'
                        ),
                        'detail': str(path),
                    })
                    self._set_risk('danger')

    # ─── Anonymous executable memory ──────────────────────────────────────────

    def _check_anon_exec_regions(self):
        """
        Searches for large anonymous executable regions in Java processes.
        JVM JIT creates many small regions; a large single block is
        a sign of reflective DLL injection or a memory-only cheat.
        """
        import psutil
        for proc in self._iter_java_procs():
            pid = proc.info['pid']
            try:
                regions = _enum_exec_memory(pid)
            except Exception:
                continue

            for r in regions:
                self.findings.append({
                    'level': 'suspicious',
                    'type': 'anon_exec_memory',
                    'message': (
                        f'Large anonymous executable region in JVM (PID {pid}) — '
                        f'possible memory-only cheat or reflective injection'
                    ),
                    'detail': (
                        f'Address: {r["base"]} | '
                        f'Size: {r["size_kb"]} KB | '
                        f'Protection: {r["protect"]}'
                    ),
                })
                self._set_risk('suspicious')

    # ─── Registry ────────────────────────────────────────────────────────────

    def _check_appinit_dlls(self):
        if not WINREG_OK:
            return
        keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'),
        ]
        for hive, subkey in keys:
            try:
                key = winreg.OpenKey(hive, subkey)
                try:
                    value, _ = winreg.QueryValueEx(key, 'AppInit_DLLs')
                    if value and value.strip():
                        self.findings.append({
                            'level': 'danger',
                            'type': 'appinit_dlls',
                            'message': 'AppInit_DLLs — global DLL injection into all processes with user32.dll',
                            'detail': f'HKLM\\{subkey}\nAppInit_DLLs={value}',
                        })
                        self._set_risk('danger')
                except FileNotFoundError:
                    pass
                finally:
                    winreg.CloseKey(key)
            except (OSError, FileNotFoundError):
                pass

    def _check_ifeo_hijacking(self):
        if not WINREG_OK:
            return
        targets = ['java.exe', 'javaw.exe', 'minecraft.exe', 'minecraftlauncher.exe']
        base = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
            for target in targets:
                try:
                    key = winreg.OpenKey(root, target)
                    try:
                        debugger, _ = winreg.QueryValueEx(key, 'Debugger')
                        if debugger:
                            self.findings.append({
                                'level': 'danger',
                                'type': 'ifeo_hijack',
                                'message': f'IFEO hijack of {target} launch',
                                'detail': f'Debugger={debugger}',
                            })
                            self._set_risk('danger')
                    except FileNotFoundError:
                        pass
                    finally:
                        winreg.CloseKey(key)
                except FileNotFoundError:
                    pass
            winreg.CloseKey(root)
        except (OSError, FileNotFoundError):
            pass

    # ─── Filesystem ──────────────────────────────────────────────────────────

    def _scan_temp_for_executables(self):
        temp_dirs = [
            Path(os.environ.get('TEMP', '')),
            Path(os.environ.get('TMP', '')),
        ]
        suspect_ext = {'.dll', '.jar', '.exe', '.bat', '.ps1', '.vbs'}

        for d in temp_dirs:
            if not d.exists():
                continue
            try:
                for entry in d.iterdir():
                    if not entry.is_file():
                        continue
                    suffix = entry.suffix.lower()
                    if suffix not in suspect_ext:
                        continue
                    name_lower = entry.name.lower()
                    is_cheat = (
                        any(k in name_lower for k in SUSPICIOUS_DLL_KEYWORDS)
                        or any(p in name_lower for p in SIGS['mod_name_patterns'])
                    )
                    level = 'danger' if is_cheat else 'suspicious'
                    self.findings.append({
                        'level': level,
                        'type': 'executable_in_temp',
                        'message': f'Подозрительный файл в TEMP: {entry.name}',
                        'detail': str(entry),
                    })
                    self._set_risk(level)
            except (PermissionError, OSError):
                pass

    def _scan_appdata_for_suspicious_dlls(self):
        for root in (self.appdata, self.localappdata):
            if not root.exists():
                continue
            try:
                for dll in root.rglob('*.dll'):
                    name_lower = dll.name.lower()
                    if any(k in name_lower for k in SUSPICIOUS_DLL_KEYWORDS):
                        self.findings.append({
                            'level': 'suspicious',
                            'type': 'suspicious_dll_in_appdata',
                            'message': f'Подозрительная DLL в AppData: {dll.name}',
                            'detail': str(dll),
                        })
                        self._set_risk('suspicious')
            except (PermissionError, OSError):
                pass

    def _check_loaded_dlls_in_java(self):
        import psutil
        for proc in self._iter_java_procs():
            pid = proc.info['pid']
            try:
                for m in proc.memory_maps():
                    path = getattr(m, 'path', '')
                    if not path.lower().endswith('.dll'):
                        continue
                    temp = os.environ.get('TEMP', '').lower()
                    tmp  = os.environ.get('TMP',  '').lower()
                    p = path.lower()
                    from_temp = (temp and p.startswith(temp)) or (tmp and p.startswith(tmp))
                    bad_name = any(k in p for k in SUSPICIOUS_DLL_KEYWORDS)
                    if from_temp or bad_name:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'suspicious_dll_loaded_in_java',
                            'message': (
                                f'Подозрительная DLL загружена в JVM '
                                f'(PID {pid}): {Path(path).name}'
                            ),
                            'detail': path,
                        })
                        self._set_risk('danger')
            except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError, OSError):
                pass

    # ─── Вспомогательный итератор ─────────────────────────────────────────────

    def _iter_java_procs(self):
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                if 'java' not in (proc.info['name'] or '').lower():
                    continue
                win_user = (proc.info.get('username') or '')
                if '\\' in win_user:
                    win_user = win_user.split('\\')[-1]
                if self.username and self.username.lower() != win_user.lower():
                    continue
                yield proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
