import os
import json
from pathlib import Path

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)

SUSPICIOUS_JVM_ARGS = [
    '-javaagent', '-agentpath', '-agentlib',
    'jdwp', 'instrument'
]


class ProcessScanner:
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        self._scan_all_processes()
        self._scan_java_processes()
        return {
            'name': 'Сканер процессов',
            'description': 'Запущенные процессы, аргументы JVM, LD_PRELOAD, инжекция .so в Java',
            'findings': self.findings,
            'risk': self.risk
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _read_proc_file(self, path):
        try:
            with open(path, 'rb') as f:
                return f.read().decode('utf-8', errors='replace')
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            return ''

    def _get_proc_uid(self, pid_dir):
        status = self._read_proc_file(pid_dir / 'status')
        for line in status.splitlines():
            if line.startswith('Uid:'):
                try:
                    return int(line.split()[1])
                except (IndexError, ValueError):
                    pass
        return None

    def _get_username_uid(self):
        import pwd
        try:
            return pwd.getpwnam(self.username).pw_uid
        except (KeyError, ImportError):
            return None

    def _scan_all_processes(self):
        proc_path = Path('/proc')
        target_uid = self._get_username_uid()

        for pid_dir in proc_path.iterdir():
            if not pid_dir.name.isdigit():
                continue

            cmdline_raw = self._read_proc_file(pid_dir / 'cmdline')
            if not cmdline_raw:
                continue

            cmdline = cmdline_raw.replace('\x00', ' ').strip()
            proc_name = Path(cmdline.split()[0]).name.lower() if cmdline.split() else ''

            uid = self._get_proc_uid(pid_dir)
            if target_uid is not None and uid != target_uid:
                continue

            for cheat in SIGS['process_names']:
                if cheat in proc_name or cheat in cmdline.lower():
                    self.findings.append({
                        'level': 'danger',
                        'type': 'known_cheat_process',
                        'pid': pid_dir.name,
                        'message': f'Известный чит-процесс: {proc_name}',
                        'detail': cmdline[:300]
                    })
                    self._set_risk('danger')
                    break

    def _scan_java_processes(self):
        proc_path = Path('/proc')
        target_uid = self._get_username_uid()
        minecraft_found = False

        for pid_dir in proc_path.iterdir():
            if not pid_dir.name.isdigit():
                continue

            cmdline_raw = self._read_proc_file(pid_dir / 'cmdline')
            if not cmdline_raw:
                continue

            cmdline = cmdline_raw.replace('\x00', ' ').strip()

            if 'java' not in cmdline.lower():
                continue

            uid = self._get_proc_uid(pid_dir)
            if target_uid is not None and uid != target_uid:
                continue

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
                        'pid': pid_dir.name,
                        'message': f'Подозрительный аргумент JVM: {arg}',
                        'detail': cmdline[:400]
                    })
                    self._set_risk(level)

            # Проверка /proc/[pid]/maps на подозрительные .so
            maps = self._read_proc_file(pid_dir / 'maps')
            for line in maps.splitlines():
                parts = line.split()
                if not parts:
                    continue
                path = parts[-1]
                if path.endswith('.so') or '.so.' in path:
                    if self._is_suspicious_so(path):
                        self.findings.append({
                            'level': 'danger',
                            'type': 'suspicious_so_injected',
                            'pid': pid_dir.name,
                            'message': f'Подозрительная библиотека в JVM: {path}',
                            'detail': line
                        })
                        self._set_risk('danger')

            # Проверка LD_PRELOAD в окружении процесса
            environ = self._read_proc_file(pid_dir / 'environ')
            for var in environ.split('\x00'):
                if var.startswith('LD_PRELOAD=') and len(var) > len('LD_PRELOAD='):
                    value = var.split('=', 1)[1]
                    self.findings.append({
                        'level': 'danger',
                        'type': 'ld_preload_in_jvm',
                        'pid': pid_dir.name,
                        'message': 'LD_PRELOAD обнаружен в окружении Java-процесса',
                        'detail': f'LD_PRELOAD={value}'
                    })
                    self._set_risk('danger')

        if not minecraft_found:
            self.findings.append({
                'level': 'info',
                'type': 'minecraft_not_running',
                'message': 'Minecraft не запущен во время проверки',
                'detail': 'Некоторые проверки требуют запущенного клиента'
            })

    def _is_suspicious_so(self, path):
        suspicious_prefixes = ('/tmp/', '/dev/shm/', '/run/user/', '/var/tmp/')
        suspicious_keywords = ['inject', 'hook', 'hack', 'cheat', 'bypass', 'loader']
        path_lower = path.lower()
        if any(path_lower.startswith(p) for p in suspicious_prefixes):
            return True
        if any(k in path_lower for k in suspicious_keywords):
            return True
        return False
