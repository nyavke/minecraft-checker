import os
import json
import subprocess
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

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)

SUSPICIOUS_JVM_ARGS = [
    '-javaagent', '-agentpath', '-agentlib',
    'jdwp', 'instrument',
]


class ProcessScanner:
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        if PSUTIL_OK:
            self._scan_all_processes()
            self._scan_java_processes()
        else:
            self.findings.append({
                'level': 'info',
                'type': 'psutil_missing',
                'message': 'psutil не установлен — расширенное сканирование процессов недоступно',
                'detail': 'pip install psutil'
            })
            self._scan_via_tasklist()

        self._check_appinit_dlls()

        return {
            'name': 'Сканер процессов',
            'description': 'Запущенные процессы, аргументы JVM, AppInit_DLLs, инжекция DLL в Java',
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _win_username(self, proc_user):
        """Вернуть имя пользователя без домена (DOMAIN\\user → user)."""
        if proc_user and '\\' in proc_user:
            return proc_user.split('\\')[-1]
        return proc_user or ''

    # ─── Fallback без psutil ───────────────────────────────────────────────────

    def _scan_via_tasklist(self):
        try:
            result = subprocess.run(
                ['tasklist', '/FO', 'CSV', '/NH'],
                capture_output=True, timeout=15,
            )
            text = result.stdout.decode('cp866', errors='replace')
            for line in text.splitlines():
                parts = line.strip('"').split('","')
                if not parts:
                    continue
                proc_name = parts[0].lower()
                for cheat in SIGS['process_names']:
                    if cheat in proc_name:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'known_cheat_process',
                            'message': f'Известный чит-процесс: {parts[0]}',
                            'detail': line.strip(),
                        })
                        self._set_risk('danger')
                        break
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    # ─── psutil-сканеры ───────────────────────────────────────────────────────

    def _scan_all_processes(self):
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                proc_name = (proc.info['name'] or '').lower()
                win_user = self._win_username(proc.info.get('username') or '')

                if self.username and self.username.lower() != win_user.lower():
                    continue

                for cheat in SIGS['process_names']:
                    if cheat in proc_name:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'known_cheat_process',
                            'pid': str(proc.info['pid']),
                            'message': f'Известный чит-процесс: {proc.info["name"]}',
                            'detail': f'PID: {proc.info["pid"]}',
                        })
                        self._set_risk('danger')
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_java_processes(self):
        import psutil
        minecraft_found = False

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                proc_name = (proc.info['name'] or '').lower()
                if 'java' not in proc_name:
                    continue

                win_user = self._win_username(proc.info.get('username') or '')
                if self.username and self.username.lower() != win_user.lower():
                    continue

                cmdline = ' '.join(proc.info['cmdline'] or [])
                is_minecraft = 'minecraft' in cmdline.lower() or 'net.minecraft' in cmdline
                if is_minecraft:
                    minecraft_found = True

                # Подозрительные аргументы JVM
                for arg in SUSPICIOUS_JVM_ARGS:
                    if arg in cmdline:
                        level = 'danger' if arg in ('-javaagent', '-agentpath', '-agentlib') else 'suspicious'
                        self.findings.append({
                            'level': level,
                            'type': 'suspicious_jvm_arg',
                            'pid': str(proc.info['pid']),
                            'message': f'Подозрительный аргумент JVM: {arg}',
                            'detail': cmdline[:400],
                        })
                        self._set_risk(level)

                # Загруженные DLL из подозрительных мест
                try:
                    for m in proc.memory_maps():
                        path = getattr(m, 'path', '')
                        if path.lower().endswith('.dll') and self._is_suspicious_dll(path):
                            self.findings.append({
                                'level': 'danger',
                                'type': 'suspicious_dll_injected',
                                'pid': str(proc.info['pid']),
                                'message': f'Подозрительная DLL загружена в JVM: {Path(path).name}',
                                'detail': path,
                            })
                            self._set_risk('danger')
                except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError, OSError):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not minecraft_found:
            self.findings.append({
                'level': 'info',
                'type': 'minecraft_not_running',
                'message': 'Minecraft не запущен во время проверки',
                'detail': 'Некоторые проверки требуют запущенного клиента',
            })

    def _is_suspicious_dll(self, path):
        temp = os.environ.get('TEMP', '').lower()
        tmp  = os.environ.get('TMP',  '').lower()
        path_lower = path.lower()
        if temp and path_lower.startswith(temp):
            return True
        if tmp and path_lower.startswith(tmp):
            return True
        keywords = ['inject', 'hook', 'hack', 'cheat', 'bypass', 'loader', 'preload']
        return any(k in path_lower for k in keywords)

    # ─── Реестр ───────────────────────────────────────────────────────────────

    def _check_appinit_dlls(self):
        if not WINREG_OK:
            return
        registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'),
        ]
        for hive, subkey in registry_keys:
            try:
                key = winreg.OpenKey(hive, subkey)
                try:
                    value, _ = winreg.QueryValueEx(key, 'AppInit_DLLs')
                    if value and value.strip():
                        self.findings.append({
                            'level': 'danger',
                            'type': 'appinit_dlls',
                            'message': 'AppInit_DLLs в реестре — глобальная инъекция DLL во все процессы',
                            'detail': f'HKLM\\{subkey}\nAppInit_DLLs={value}',
                        })
                        self._set_risk('danger')
                except FileNotFoundError:
                    pass
                finally:
                    winreg.CloseKey(key)
            except (OSError, FileNotFoundError):
                pass
