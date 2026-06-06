import os
import re
import json
from pathlib import Path
from datetime import datetime, timedelta
from detectors._resources import resource_path

try:
    import winreg
    WINREG_OK = True
except ImportError:
    WINREG_OK = False

with open(resource_path('signatures/cheats.json'), encoding='utf-8') as f:
    SIGS = json.load(f)

SUSPICIOUS_HISTORY_KEYWORDS = [
    'javaagent', 'agentpath', 'agentlib',
    'wurst', 'liquidbounce', 'meteor', 'impact', 'sigma',
    'autoclicker', 'autoclick',
    'cheat', 'hack', 'bypass', 'ghostclient',
    r'wget.*\.jar', r'curl.*\.jar', r'Invoke-WebRequest.*\.jar',
    r'iwr.*\.jar',
    'inject', 'dll.*inject',
]

RUN_REGISTRY_KEYS = [
    (None, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
    (None, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
    (None, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
]


class FilesystemScanner:
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

        current = os.environ.get('USERNAME', '')
        if not username or username.lower() == current.lower():
            self.appdata     = Path(os.environ.get('APPDATA',      ''))
            self.localappdata = Path(os.environ.get('LOCALAPPDATA', ''))
            self.userprofile  = Path(os.environ.get('USERPROFILE',  ''))
        else:
            self.userprofile  = Path('C:/Users') / username
            self.appdata      = self.userprofile / 'AppData' / 'Roaming'
            self.localappdata = self.userprofile / 'AppData' / 'Local'

    def scan(self):
        self._check_powershell_history()
        self._check_cmd_history()
        self._check_startup_folder()
        self._check_registry_run_keys()
        self._check_recently_modified_jars()
        self._check_suspicious_hidden_dirs()
        self._check_scheduled_tasks()
        self._scan_disk_c()           # Тема 4 — весь диск C
        self._scan_minecraft_config() # Тема 3 — папка config
        self._scan_nvidia_profiles()  # Тема 2.3 — NVIDIA история
        return {
            'name': 'Сканер файловой системы',
            'description': (
                'История команд, автозапуск, реестр, JAR, планировщик, '
                'диск C (Program Files / ProgramData / корень), '
                'конфиги Minecraft, NVIDIA история запусков'
            ),
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    # ─── История команд ────────────────────────────────────────────────────────

    def _check_powershell_history(self):
        ps_history = (
            self.appdata
            / 'Microsoft' / 'Windows' / 'PowerShell'
            / 'PSReadLine' / 'ConsoleHost_history.txt'
        )
        if not ps_history.exists():
            return
        try:
            content = ps_history.read_text(encoding='utf-8', errors='replace')
            self._scan_history_text(content, 'ConsoleHost_history.txt')
        except (PermissionError, OSError):
            pass

    def _check_cmd_history(self):
        # CMD история хранится только в реестре — HKCU\Console
        # Более полезный источник: файлы .bat в temp
        pass

    def _scan_history_text(self, content, filename):
        for pattern in SUSPICIOUS_HISTORY_KEYWORDS:
            matches = re.findall(rf'.{{0,80}}{pattern}.{{0,80}}', content, re.IGNORECASE)
            for match in matches[:3]:
                self.findings.append({
                    'level': 'suspicious',
                    'type': 'suspicious_history',
                    'message': f'Подозрительная команда в {filename}',
                    'detail': match.strip(),
                })
                self._set_risk('suspicious')

    # ─── Автозапуск ───────────────────────────────────────────────────────────

    def _check_startup_folder(self):
        startup_dirs = [
            self.appdata / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup',
            Path('C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp'),
        ]
        for startup in startup_dirs:
            if not startup.exists():
                continue
            try:
                for entry in startup.iterdir():
                    if not entry.is_file():
                        continue
                    try:
                        content = entry.read_text(encoding='utf-8', errors='replace').lower()
                        for cheat in SIGS['mod_name_patterns']:
                            if cheat in content or cheat in entry.name.lower():
                                self.findings.append({
                                    'level': 'danger',
                                    'type': 'cheat_in_startup',
                                    'message': f'Упоминание чита в папке автозапуска: {entry.name}',
                                    'detail': f'Паттерн: {cheat} | Путь: {entry}',
                                })
                                self._set_risk('danger')
                                break
                        else:
                            if entry.suffix.lower() in ('.exe', '.bat', '.cmd', '.ps1', '.vbs', '.jar'):
                                self.findings.append({
                                    'level': 'suspicious',
                                    'type': 'executable_in_startup',
                                    'message': f'Исполняемый файл в папке автозапуска: {entry.name}',
                                    'detail': str(entry),
                                })
                                self._set_risk('suspicious')
                    except (PermissionError, OSError, UnicodeDecodeError):
                        pass
            except (PermissionError, OSError):
                pass

    def _check_registry_run_keys(self):
        if not WINREG_OK:
            return
        hives = [
            (winreg.HKEY_CURRENT_USER,  'HKCU'),
            (winreg.HKEY_LOCAL_MACHINE, 'HKLM'),
        ]
        subkeys = [
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        ]
        for hive, hive_name in hives:
            for subkey in subkeys:
                try:
                    key = winreg.OpenKey(hive, subkey)
                    idx = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, idx)
                            idx += 1
                            val_lower = value.lower()
                            for cheat in SIGS['mod_name_patterns']:
                                if cheat in val_lower or cheat in name.lower():
                                    self.findings.append({
                                        'level': 'danger',
                                        'type': 'cheat_in_run_key',
                                        'message': f'Чит в ключе автозапуска реестра: {name}',
                                        'detail': f'{hive_name}\\{subkey}\n{name}={value}',
                                    })
                                    self._set_risk('danger')
                                    break
                            else:
                                # Подозрительные пути (TEMP, AppData без имён из белого списка)
                                temp = os.environ.get('TEMP', '').lower()
                                if temp and temp in val_lower and (
                                    val_lower.endswith('.exe') or val_lower.endswith('.jar')
                                ):
                                    self.findings.append({
                                        'level': 'suspicious',
                                        'type': 'temp_in_run_key',
                                        'message': f'Запуск из TEMP в ключе реестра: {name}',
                                        'detail': f'{hive_name}\\{subkey}\n{name}={value}',
                                    })
                                    self._set_risk('suspicious')
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except (OSError, FileNotFoundError):
                    pass

    # ─── Файлы ────────────────────────────────────────────────────────────────

    def _check_recently_modified_jars(self):
        cutoff = datetime.now() - timedelta(days=7)
        scan_roots = [self.appdata, self.localappdata, self.userprofile / 'Downloads']

        for root in scan_roots:
            if not root.exists():
                continue
            try:
                for jar in root.rglob('*.jar'):
                    try:
                        mtime = datetime.fromtimestamp(jar.stat().st_mtime)
                        if mtime < cutoff:
                            continue
                        name_lower = jar.name.lower()
                        for pattern in SIGS['mod_name_patterns']:
                            if pattern in name_lower:
                                self.findings.append({
                                    'level': 'danger',
                                    'type': 'recent_cheat_jar',
                                    'message': f'Недавно изменённый JAR с признаком чита: {jar.name}',
                                    'detail': f'Изменён: {mtime.strftime("%Y-%m-%d %H:%M")} | Путь: {jar}',
                                })
                                self._set_risk('danger')
                                break
                    except (OSError, PermissionError):
                        pass
            except (PermissionError, OSError):
                pass

    def _check_suspicious_hidden_dirs(self):
        """Скрытые папки в AppData с JAR/DLL файлами."""
        legit = {
            '.minecraft', 'minecraft', 'prism', 'prismlauncher', 'multimc',
            'tlauncher', 'lunarclient', 'feather', 'curseforge',
            'microsoft', 'mozilla', 'google', 'discord', 'slack',
            'visual studio code', 'code', 'npm', 'pip',
        }
        for root in (self.appdata, self.localappdata):
            if not root.exists():
                continue
            try:
                for entry in root.iterdir():
                    if not entry.is_dir():
                        continue
                    name_lower = entry.name.lower().lstrip('.')
                    if name_lower in legit:
                        continue
                    try:
                        jar_count = len(list(entry.rglob('*.jar')))
                        dll_count = len(list(entry.rglob('*.dll')))
                        if jar_count > 0 or dll_count > 0:
                            # Проверяем на совпадение с именами читов
                            is_cheat = any(p in entry.name.lower() for p in SIGS['mod_name_patterns'])
                            level = 'danger' if is_cheat else 'suspicious'
                            self.findings.append({
                                'level': level,
                                'type': 'suspicious_dir_with_binaries',
                                'message': f'Подозрительная папка с исполняемыми: {entry.name}',
                                'detail': (
                                    f'.jar файлов: {jar_count}, .dll файлов: {dll_count} | Путь: {entry}'
                                ),
                            })
                            self._set_risk(level)
                    except (PermissionError, OSError):
                        pass
            except (PermissionError, OSError):
                pass

    def _check_scheduled_tasks(self):
        """Проверяем задачи планировщика на упоминания читов (через schtasks)."""
        try:
            import subprocess
            result = subprocess.run(
                ['schtasks', '/query', '/FO', 'CSV', '/NH'],
                capture_output=True, timeout=15,
            )
            output = result.stdout.decode('cp866', errors='replace')
            for line in output.splitlines():
                line_lower = line.lower()
                for cheat in SIGS['mod_name_patterns']:
                    if cheat in line_lower:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'cheat_scheduled_task',
                            'message': f'Упоминание чита в задаче планировщика',
                            'detail': line.strip(),
                        })
                        self._set_risk('danger')
                        break
        except Exception:
            pass

    # ─── Тема 4 | Проверка всего диска C ─────────────────────────────────────

    def _scan_disk_c(self):
        """
        Мануал Тема 4: после включения скрытых файлов проверить весь диск C.
        Читы прячутся в Program Files (x86), ProgramData, корне C:\ и т.д.
        под именами легитимных программ (например ASIO4ALL v2\\ExpensiveClient.exe).
        """
        # Только конкретные имена читов — НЕ generic слова вроде inject/hook/loader
        ALL_PATTERNS = list({
            p for p in (SIGS['mod_name_patterns'] + SIGS['process_names'])
            if len(p) >= 4 and p not in {
                'hack', 'hook', 'inject', 'loader', 'patch', 'bypass',
                'quick', 'payload', 'preload', 'aimbot', 'cheat',
                'fly', 'speed', 'delta', 'reach', 'scaffold', 'esp',
                'moon', 'virgin', 'rich', 'wild', 'ares', 'vapor',
                'remix', 'pyro', 'future', 'impact', 'sigma', 'nodus',
            }
        })

        # Пути которые точно легитимны — пропускаем без проверки
        LEGIT_PATH_FRAGMENTS = {
            'git', 'obs-studio', 'visual studio', 'vscode', 'android studio',
            'wsl', 'microsoft office', 'windows defender', 'dotnet', 'mozilla',
            'google', 'discord', 'steam', 'epic games', 'wargaming',
            'netease', 'mumuplayer', 'qt', 'flyfroglc', 'happ',
            'dependencyinjection', 'obs_studio', 'rudesktop',
        }

        scan_roots = [
            Path('C:/'),
            Path('C:/Program Files'),
            Path('C:/Program Files (x86)'),
            Path('C:/ProgramData'),
            Path('C:/Windows/Temp'),
            Path('C:/Users/Public'),
        ]

        suspect_ext = {'.exe', '.dll', '.jar', '.bat', '.cmd', '.ps1', '.vbs'}
        found = set()
        MAX_FILES = 5000  # лимит файлов — защита от зависания на больших системах

        for root in scan_roots:
            if not root.exists():
                continue

            # Для корня C:\ и Program Files — итерируем только первый уровень папок,
            # затем ищем файлы внутри каждой подпапки (глубина 2)
            try:
                top_entries = list(root.iterdir())
            except (PermissionError, OSError):
                continue

            for top in top_entries:
                # Пропускаем системные папки
                if top.name.lower() in {
                    'windows', '$recycle.bin', 'system volume information',
                    'recovery', '$winreagent', 'msocache',
                }:
                    continue
                # Пропускаем легитимные пути
                top_path_lower = str(top).lower()
                if any(f in top_path_lower for f in LEGIT_PATH_FRAGMENTS):
                    continue

                # Проверяем само имя папки/файла
                top_lower = top.name.lower()
                for pat in ALL_PATTERNS:
                    if pat and pat in top_lower and top_lower not in found:
                        found.add(top_lower)
                        self.findings.append({
                            'level': 'danger',
                            'type': 'disk_c_cheat_name',
                            'message': f'Диск C: чит обнаружен — {top.name}',
                            'detail': str(top),
                        })
                        self._set_risk('danger')
                        break

                # Рекурсивный поиск файлов (глубина 3 от текущего корня)
                if top.is_dir():
                    try:
                        for depth1 in top.iterdir():
                            if len(found) >= MAX_FILES:
                                break
                            self._check_entry(depth1, ALL_PATTERNS, suspect_ext, found)
                            if depth1.is_dir():
                                try:
                                    for depth2 in depth1.iterdir():
                                        if len(found) >= MAX_FILES:
                                            break
                                        self._check_entry(depth2, ALL_PATTERNS, suspect_ext, found)
                                except (PermissionError, OSError):
                                    pass
                    except (PermissionError, OSError):
                        pass
                else:
                    self._check_entry(top, ALL_PATTERNS, suspect_ext, found)

    # Легитимные фрагменты путей — не алертим если путь содержит их
    _LEGIT_FRAGMENTS = {
        'git', 'obs-studio', 'visual studio', 'vscode', 'android studio',
        'wsl', 'microsoft office', 'windows defender', 'dotnet', 'mozilla',
        'google', 'discord', 'steam', 'epic games', 'wargaming',
        'netease', 'mumuplayer', 'qt', 'flyfroglc', 'happ',
        'dependencyinjection', 'obs_studio', 'rudesktop', 'minecraft',
    }

    def _check_entry(self, entry: Path, patterns, suspect_ext, found: set):
        """Проверить один файл/папку на совпадение с читами."""
        if not entry.is_file():
            return
        if entry.suffix.lower() not in suspect_ext:
            return
        path_lower = str(entry).lower()
        # Пропускаем легитимные пути
        if any(f in path_lower for f in self._LEGIT_FRAGMENTS):
            return
        name_lower = entry.name.lower()
        key = path_lower
        if key in found:
            return
        for pat in patterns:
            if pat and pat in name_lower:
                found.add(key)
                self.findings.append({
                    'level': 'danger',
                    'type': 'disk_c_cheat_file',
                    'message': f'Диск C: чит-файл — {entry.name}',
                    'detail': str(entry),
                })
                self._set_risk('danger')
                return

    # ─── Тема 3 — .minecraft/config ──────────────────────────────────────────

    def _scan_minecraft_config(self):
        """
        Мануал Тема 3 пункт 1: в папке config могут лежать конфиги запрещённых
        модов или читов даже если сами JAR удалены.
        """
        mc_config = self.appdata / '.minecraft' / 'config'
        if not mc_config.exists():
            return
        try:
            for entry in mc_config.iterdir():
                name_lower = entry.name.lower()
                for pat in SIGS['mod_name_patterns']:
                    if pat in name_lower:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'minecraft_cheat_config',
                            'message': f'.minecraft/config: конфиг чита — {entry.name}',
                            'detail': str(entry),
                        })
                        self._set_risk('danger')
                        break
        except (PermissionError, OSError):
            pass

    # ─── Тема 2.3 — NVIDIA Control Panel (история EXE) ───────────────────────

    def _scan_nvidia_profiles(self):
        """
        Мануал Тема 2.3: NVIDIA хранит профили ВСЕХ когда-либо запущенных EXE
        в реестре. Показывает читы даже если файлы удалены.
        """
        if not WINREG_OK:
            return

        nvidia_keys = [
            r'SOFTWARE\NVIDIA Corporation\Global\NvCplApi\Profiles',
            r'SOFTWARE\NVIDIA Corporation\NVControlPanel2\Clients',
        ]

        for subkey in nvidia_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
                idx = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, idx)
                        idx += 1
                        name_lower = name.lower()
                        for pat in SIGS['mod_name_patterns'] + SIGS['process_names']:
                            if pat and pat in name_lower:
                                self.findings.append({
                                    'level': 'danger',
                                    'type': 'nvidia_cheat_profile',
                                    'message': f'NVIDIA: чит запускался — {name}',
                                    'detail': f'HKLM\\{subkey}\\{name}',
                                })
                                self._set_risk('danger')
                                break
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, FileNotFoundError):
                pass
