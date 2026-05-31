import os
import re
import json
import stat
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)

# Ключевые слова для истории команд
SUSPICIOUS_HISTORY_KEYWORDS = [
    'inject', 'ld_preload', 'ptrace', 'javaagent', 'agentpath',
    'wurst', 'liquidbounce', 'meteor', 'impact', 'sigma',
    'autoclicker', 'xdotool', 'ydotool', 'xte',
    'cheat', 'hack', 'bypass', 'ghostclient',
    'wget.*\\.jar', 'curl.*\\.jar',
    'chmod.*\\+x.*/tmp', 'python.*autoclick',
]

# Подозрительные autostart-пути
AUTOSTART_PATHS = [
    '~/.config/autostart',
    '~/.local/share/systemd/user',
    '/etc/systemd/system',
    '~/.config/systemd/user',
]


class FilesystemScanner:
    def __init__(self, username):
        self.username = username
        self.home = Path(f'/home/{username}')
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        self._check_shell_history()
        self._check_autostart()
        self._check_recently_modified_jars()
        self._check_hidden_dirs_in_home()
        self._check_systemd_user_services()
        return {
            'name': 'Сканер файловой системы',
            'description': 'История команд, автозапуск, недавно изменённые JAR, скрытые папки',
            'findings': self.findings,
            'risk': self.risk
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _expand(self, path_str):
        return Path(path_str.replace('~', str(self.home)))

    def _check_shell_history(self):
        history_files = [
            self.home / '.bash_history',
            self.home / '.zsh_history',
            self.home / '.local/share/fish/fish_history',
        ]

        for hist_file in history_files:
            if not hist_file.exists():
                continue
            try:
                content = hist_file.read_text(errors='replace')
                for pattern in SUSPICIOUS_HISTORY_KEYWORDS:
                    matches = re.findall(rf'.{{0,60}}{pattern}.{{0,60}}', content, re.IGNORECASE)
                    for match in matches[:3]:  # Максимум 3 совпадения на паттерн
                        self.findings.append({
                            'level': 'suspicious',
                            'type': 'suspicious_history',
                            'message': f'Подозрительная команда в {hist_file.name}',
                            'detail': match.strip()
                        })
                        self._set_risk('suspicious')
            except (PermissionError, OSError):
                pass

    def _check_autostart(self):
        for path_str in AUTOSTART_PATHS:
            autostart_dir = self._expand(path_str)
            if not autostart_dir.exists():
                continue
            try:
                for entry in autostart_dir.iterdir():
                    if entry.suffix in ('.desktop', '.service', '.sh', '') or entry.is_file():
                        try:
                            content = entry.read_text(errors='replace').lower()
                            # Проверяем на признаки читов
                            for cheat in SIGS['mod_name_patterns']:
                                if cheat in content:
                                    self.findings.append({
                                        'level': 'danger',
                                        'type': 'cheat_in_autostart',
                                        'message': f'Упоминание чита в автозапуске: {entry.name}',
                                        'detail': f'Паттерн: {cheat} | Путь: {entry}'
                                    })
                                    self._set_risk('danger')
                                    break
                            # Подозрительные исполняемые в autostart
                            if entry.suffix in ('', '.sh') and os.access(str(entry), os.X_OK):
                                self.findings.append({
                                    'level': 'suspicious',
                                    'type': 'executable_in_autostart',
                                    'message': f'Исполняемый файл в автозапуске: {entry.name}',
                                    'detail': str(entry)
                                })
                                self._set_risk('suspicious')
                        except (PermissionError, OSError):
                            pass
            except (PermissionError, OSError):
                pass

    def _check_recently_modified_jars(self):
        if not self.home.exists():
            return

        cutoff = datetime.now() - timedelta(days=7)
        suspicious_count = 0

        for jar in self.home.rglob('*.jar'):
            try:
                mtime = datetime.fromtimestamp(jar.stat().st_mtime)
                if mtime > cutoff:
                    name_lower = jar.name.lower()
                    for pattern in SIGS['mod_name_patterns']:
                        if pattern in name_lower:
                            self.findings.append({
                                'level': 'danger',
                                'type': 'recent_cheat_jar',
                                'message': f'Недавно изменённый JAR с признаком чита: {jar.name}',
                                'detail': f'Изменён: {mtime.strftime("%Y-%m-%d %H:%M")} | Путь: {jar}'
                            })
                            self._set_risk('danger')
                            break
            except (OSError, PermissionError):
                pass

    def _check_hidden_dirs_in_home(self):
        if not self.home.exists():
            return

        # Легитимные скрытые папки Minecraft-клиентов
        legit_hidden = {
            '.minecraft', '.lunarclient', '.feather', '.tlauncher',
            '.config', '.local', '.cache', '.java', '.ssh',
            '.bashrc', '.zshrc', '.profile', '.bash_history',
            '.gnupg', '.mozilla', '.thunderbird', '.wine'
        }

        try:
            for entry in self.home.iterdir():
                if entry.name.startswith('.') and entry.is_dir():
                    if entry.name not in legit_hidden:
                        # Проверим содержимое
                        try:
                            jar_count = len(list(entry.rglob('*.jar')))
                            so_count = len(list(entry.rglob('*.so')))
                            if jar_count > 0 or so_count > 0:
                                self.findings.append({
                                    'level': 'suspicious',
                                    'type': 'hidden_dir_with_binaries',
                                    'message': f'Скрытая папка с исполняемыми: {entry.name}',
                                    'detail': f'.jar файлов: {jar_count}, .so файлов: {so_count} | Путь: {entry}'
                                })
                                self._set_risk('suspicious')
                        except (PermissionError, OSError):
                            pass
        except (PermissionError, OSError):
            pass

    def _check_systemd_user_services(self):
        service_dirs = [
            self.home / '.config' / 'systemd' / 'user',
            self.home / '.local' / 'share' / 'systemd' / 'user',
        ]

        for service_dir in service_dirs:
            if not service_dir.exists():
                continue
            try:
                for service_file in service_dir.glob('*.service'):
                    try:
                        content = service_file.read_text(errors='replace').lower()
                        for cheat in SIGS['mod_name_patterns']:
                            if cheat in content:
                                self.findings.append({
                                    'level': 'danger',
                                    'type': 'cheat_systemd_service',
                                    'message': f'Упоминание чита в systemd-сервисе: {service_file.name}',
                                    'detail': f'Паттерн: {cheat}'
                                })
                                self._set_risk('danger')
                                break
                        # Проверяем на java с подозрительными аргументами
                        if 'javaagent' in content or 'agentpath' in content:
                            self.findings.append({
                                'level': 'danger',
                                'type': 'javaagent_in_service',
                                'message': f'javaagent/agentpath в systemd-сервисе: {service_file.name}',
                                'detail': ''
                            })
                            self._set_risk('danger')
                    except (PermissionError, OSError):
                        pass
            except (PermissionError, OSError):
                pass
