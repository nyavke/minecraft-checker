import re
import json
import subprocess
from pathlib import Path

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)


class NetworkScanner:
    """
    Проверяет сетевые соединения Java-процессов:
    подключения к известным серверам читов, подозрительные порты.
    """
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        connections = self._get_connections()
        if connections is not None:
            self._analyze_connections(connections)
        return {
            'name': 'Сканер сети',
            'description': 'Активные соединения Java-процессов, подключения к известным серверам читов',
            'findings': self.findings,
            'risk': self.risk
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _get_connections(self):
        try:
            result = subprocess.run(
                ['ss', '-tulnp'],
                capture_output=True, text=True, timeout=10
            )
            connections = result.stdout

            # Также получаем установленные соединения
            result2 = subprocess.run(
                ['ss', '-tp', 'state', 'established'],
                capture_output=True, text=True, timeout=10
            )
            return connections + '\n' + result2.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            try:
                result = subprocess.run(
                    ['netstat', '-tulnp'],
                    capture_output=True, text=True, timeout=10
                )
                return result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.findings.append({
                    'level': 'info',
                    'type': 'network_tools_unavailable',
                    'message': 'ss и netstat недоступны — проверка соединений пропущена',
                    'detail': ''
                })
                return None

    def _analyze_connections(self, connections_output):
        java_pids = self._get_java_pids()

        # Ищем подключения к известным доменам читов
        for line in connections_output.splitlines():
            line_lower = line.lower()
            for domain in SIGS['suspicious_domains']:
                if domain in line_lower:
                    self.findings.append({
                        'level': 'danger',
                        'type': 'cheat_server_connection',
                        'message': f'Обнаружено подключение к серверу чита: {domain}',
                        'detail': line.strip()
                    })
                    self._set_risk('danger')

        # Ищем Java-процессы с нестандартными входящими соединениями
        # JDWP (Java Debug Wire Protocol) — порт 5005 по умолчанию
        if ':5005' in connections_output or ':8000' in connections_output:
            self.findings.append({
                'level': 'suspicious',
                'type': 'jdwp_port_open',
                'message': 'Открыт порт отладки JVM (JDWP) — возможен удалённый доступ к Java-процессу',
                'detail': 'Порты 5005 или 8000 открыты'
            })
            self._set_risk('suspicious')

        if not self.findings:
            self.findings.append({
                'level': 'info',
                'type': 'no_suspicious_connections',
                'message': 'Подозрительных сетевых соединений не обнаружено',
                'detail': ''
            })

    def _get_java_pids(self):
        pids = []
        proc_path = Path('/proc')
        try:
            import pwd
            target_uid = pwd.getpwnam(self.username).pw_uid
        except (KeyError, ImportError):
            target_uid = None

        for pid_dir in proc_path.iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                cmdline_path = pid_dir / 'cmdline'
                if not cmdline_path.exists():
                    continue
                with open(cmdline_path, 'rb') as f:
                    cmdline = f.read().decode('utf-8', errors='replace').replace('\x00', ' ')
                if 'java' in cmdline.lower():
                    pids.append(pid_dir.name)
            except (PermissionError, FileNotFoundError):
                continue
        return pids
