import os
import json
import subprocess
from pathlib import Path

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)


class NativeScanner:
    """
    Проверяет native-уровень: .so файлы, LD_PRELOAD глобально,
    /proc/maps всех процессов пользователя, JNI библиотеки.
    """
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        self._check_global_ld_preload()
        self._scan_user_home_for_so()
        self._scan_tmp_for_executables()
        self._check_proc_maps_for_user()
        return {
            'name': 'Сканер native-библиотек',
            'description': 'LD_PRELOAD, .so-файлы в /tmp и домашней папке, инжекция через /proc/maps',
            'findings': self.findings,
            'risk': self.risk
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _check_global_ld_preload(self):
        # /etc/ld.so.preload
        preload_file = Path('/etc/ld.so.preload')
        if preload_file.exists():
            try:
                content = preload_file.read_text().strip()
                if content:
                    self.findings.append({
                        'level': 'danger',
                        'type': 'global_ld_preload',
                        'message': 'Обнаружен /etc/ld.so.preload — глобальная инъекция библиотек',
                        'detail': content
                    })
                    self._set_risk('danger')
            except PermissionError:
                pass

        # ~/.bashrc / ~/.profile / ~/.zshrc на LD_PRELOAD
        shell_files = [
            f'/home/{self.username}/.bashrc',
            f'/home/{self.username}/.bash_profile',
            f'/home/{self.username}/.profile',
            f'/home/{self.username}/.zshrc',
            f'/home/{self.username}/.zprofile',
            f'/home/{self.username}/.config/fish/config.fish',
        ]
        for sf in shell_files:
            p = Path(sf)
            if not p.exists():
                continue
            try:
                content = p.read_text(errors='replace')
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith('#'):
                        continue
                    if 'LD_PRELOAD' in stripped and '=' in stripped:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'ld_preload_in_shell_config',
                            'message': f'LD_PRELOAD в конфиге оболочки: {p.name}',
                            'detail': stripped
                        })
                        self._set_risk('danger')
            except (PermissionError, OSError):
                pass

    def _scan_user_home_for_so(self):
        home = Path(f'/home/{self.username}')
        if not home.exists():
            return

        suspicious_prefixes = ('/tmp', '/dev/shm', '/run/user', '/var/tmp')

        for so_file in home.rglob('*.so'):
            path_str = str(so_file)
            name_lower = so_file.name.lower()
            suspicious_keywords = ['inject', 'hook', 'hack', 'cheat', 'bypass', 'loader', 'preload']

            if any(k in name_lower for k in suspicious_keywords):
                self.findings.append({
                    'level': 'danger',
                    'type': 'suspicious_so_in_home',
                    'message': f'Подозрительная .so библиотека в домашней папке: {so_file.name}',
                    'detail': path_str
                })
                self._set_risk('danger')

    def _scan_tmp_for_executables(self):
        scan_dirs = ['/tmp', '/dev/shm', '/var/tmp', f'/run/user/{self._get_uid()}']
        extensions = ('.so', '.jar', '.py', '.sh', '')

        for dir_path in scan_dirs:
            d = Path(dir_path)
            if not d.exists():
                continue
            try:
                for entry in d.iterdir():
                    if entry.is_file():
                        is_exec = os.access(str(entry), os.X_OK)
                        is_suspicious_ext = any(
                            entry.name.endswith(ext) for ext in extensions if ext
                        ) or (is_exec and '.' not in entry.name)

                        if is_exec or entry.suffix in ('.so', '.jar'):
                            self.findings.append({
                                'level': 'suspicious',
                                'type': 'executable_in_tmp',
                                'message': f'Исполняемый файл в {dir_path}: {entry.name}',
                                'detail': str(entry)
                            })
                            self._set_risk('suspicious')
            except (PermissionError, OSError):
                pass

    def _check_proc_maps_for_user(self):
        target_uid = self._get_uid()
        if target_uid is None:
            return

        proc_path = Path('/proc')
        for pid_dir in proc_path.iterdir():
            if not pid_dir.name.isdigit():
                continue

            try:
                # Проверяем владельца процесса
                status_path = pid_dir / 'status'
                if not status_path.exists():
                    continue
                with open(status_path) as f:
                    uid = None
                    for line in f:
                        if line.startswith('Uid:'):
                            try:
                                uid = int(line.split()[1])
                            except (IndexError, ValueError):
                                pass
                            break
                if uid != target_uid:
                    continue

                maps_path = pid_dir / 'maps'
                if not maps_path.exists():
                    continue
                with open(maps_path) as f:
                    for line in f:
                        parts = line.split()
                        if not parts:
                            continue
                        mapped = parts[-1]
                        if not mapped.startswith('/'):
                            continue
                        for sus_path in SIGS['suspicious_paths']:
                            if mapped.startswith(sus_path):
                                self.findings.append({
                                    'level': 'danger',
                                    'type': 'suspicious_mapped_region',
                                    'message': f'Файл из подозрительного пути загружен в память (PID {pid_dir.name})',
                                    'detail': mapped
                                })
                                self._set_risk('danger')
                                break

            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue

    def _get_uid(self):
        try:
            import pwd
            return pwd.getpwnam(self.username).pw_uid
        except (KeyError, ImportError):
            return None
