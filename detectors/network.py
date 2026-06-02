import json
import subprocess
from pathlib import Path

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)

# Порты отладки JVM (JDWP)
JDWP_PORTS = {5005, 8000, 9009}


class NetworkScanner:
    """
    Проверяет сетевые соединения Java-процессов:
    подключения к известным серверам читов, отладочные порты JVM.
    """

    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        if PSUTIL_OK:
            self._scan_via_psutil()
        else:
            self._scan_via_netstat()
        return {
            'name': 'Сканер сети',
            'description': 'Активные соединения Java-процессов, подключения к серверам читов, JDWP',
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    # ─── psutil-путь ──────────────────────────────────────────────────────────

    def _scan_via_psutil(self):
        import psutil

        # Собираем PID всех Java-процессов целевого пользователя
        java_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                if 'java' not in (proc.info['name'] or '').lower():
                    continue
                win_user = (proc.info.get('username') or '')
                if '\\' in win_user:
                    win_user = win_user.split('\\')[-1]
                if self.username and self.username.lower() != win_user.lower():
                    continue
                java_pids.add(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not java_pids:
            self.findings.append({
                'level': 'info',
                'type': 'no_java_processes',
                'message': 'Java-процессы не найдены — сетевая проверка пропущена',
                'detail': '',
            })
            return

        found_suspicious = False

        try:
            conns = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            self.findings.append({
                'level': 'info',
                'type': 'net_access_denied',
                'message': 'Нет прав для просмотра всех соединений — запустите от имени администратора',
                'detail': '',
            })
            return

        for conn in conns:
            # Фильтр по Java-PID (psutil может вернуть None для pid)
            if conn.pid not in java_pids:
                continue

            raddr = conn.raddr
            if not raddr:
                continue

            rip   = raddr.ip   if hasattr(raddr, 'ip')   else ''
            rport = raddr.port if hasattr(raddr, 'port') else 0

            addr_str = f'{rip}:{rport}'

            # Подключения к известным доменам читов (по IP-строке — ограничено,
            # но резолвинг IP по именам здесь неуместен)
            for domain in SIGS['suspicious_domains']:
                if domain in addr_str:
                    self.findings.append({
                        'level': 'danger',
                        'type': 'cheat_server_connection',
                        'message': f'Подключение Java к серверу чита: {domain}',
                        'detail': f'PID {conn.pid} → {addr_str}',
                    })
                    self._set_risk('danger')
                    found_suspicious = True

            # JDWP-отладочные порты
            lport = conn.laddr.port if conn.laddr else 0
            if lport in JDWP_PORTS or rport in JDWP_PORTS:
                self.findings.append({
                    'level': 'suspicious',
                    'type': 'jdwp_port',
                    'message': f'Открыт JDWP-порт отладки JVM: {lport or rport}',
                    'detail': f'PID {conn.pid} | статус: {conn.status}',
                })
                self._set_risk('suspicious')
                found_suspicious = True

        if not found_suspicious:
            self.findings.append({
                'level': 'info',
                'type': 'no_suspicious_connections',
                'message': 'Подозрительных сетевых соединений не обнаружено',
                'detail': f'Проверено Java-процессов: {len(java_pids)}',
            })

    # ─── Fallback через netstat ────────────────────────────────────────────────

    def _scan_via_netstat(self):
        try:
            result = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True, timeout=15,
            )
            output = result.stdout.decode('cp866', errors='replace')
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            self.findings.append({
                'level': 'info',
                'type': 'network_tools_unavailable',
                'message': 'netstat недоступен — сетевая проверка пропущена',
                'detail': '',
            })
            return

        found_suspicious = False

        for line in output.splitlines():
            line_lower = line.lower()

            for domain in SIGS['suspicious_domains']:
                if domain in line_lower:
                    self.findings.append({
                        'level': 'danger',
                        'type': 'cheat_server_connection',
                        'message': f'Подключение к серверу чита: {domain}',
                        'detail': line.strip(),
                    })
                    self._set_risk('danger')
                    found_suspicious = True

            for port in JDWP_PORTS:
                if f':{port}' in line:
                    self.findings.append({
                        'level': 'suspicious',
                        'type': 'jdwp_port',
                        'message': f'Открыт JDWP-порт отладки JVM: {port}',
                        'detail': line.strip(),
                    })
                    self._set_risk('suspicious')
                    found_suspicious = True

        if not found_suspicious:
            self.findings.append({
                'level': 'info',
                'type': 'no_suspicious_connections',
                'message': 'Подозрительных сетевых соединений не обнаружено',
                'detail': '',
            })
