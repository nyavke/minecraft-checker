"""
DNS Cache Scanner — проверяет кеш DNS на обращения к доменам читерских клиентов.
Кеш сохраняется после закрытия игры — можно обнаружить чит, который уже удалён.
"""

import subprocess
import re
import json
from pathlib import Path
from detectors._resources import resource_path

with open(resource_path('signatures/cheats.json'), encoding='utf-8') as f:
    _SIGS = json.load(f)

# Известные домены читерских клиентов — только без пути (убираем vk.com/group)
_CHEAT_DOMAINS = [
    d.lower() for d in _SIGS.get('suspicious_domains', [])
    if '/' not in d
]

# Паттерны имён: только ≥6 символов, длинные первыми (жадный match)
_NAME_PATTERNS = sorted(
    {p.lower() for p in _SIGS['process_names'] + _SIGS['mod_name_patterns'] if len(p) >= 6},
    key=len, reverse=True,
)

# Строки вида ": domain.tld" в конце строки (EN и RU Windows)
_FQDN_RE = re.compile(
    r':\s+([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)+\.[a-zA-Z]{2,})\s*$',
    re.MULTILINE,
)


class DNSCacheScanner:

    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk     = 'clean'

    def _set_risk(self, level: str):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def scan(self) -> dict:
        for domain in sorted(self._get_cached_domains()):
            self._check_domain(domain)
        return {
            'name':        'DNS Cache',
            'description': 'Кеш DNS — обращения к доменам читерских клиентов (виден после закрытия игры)',
            'findings':    self.findings,
            'risk':        self.risk,
        }

    def _get_cached_domains(self) -> set:
        try:
            proc = subprocess.run(
                ['ipconfig', '/displaydns'],
                capture_output=True,
                timeout=10,
            )
            raw = proc.stdout
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return set()

        # UTF-8 (chcp 65001 из bat), CP866 (OEM русский), CP1251
        for enc in ('utf-8', 'cp866', 'cp1251'):
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            text = raw.decode('utf-8', errors='replace')

        domains: set = set()
        for m in _FQDN_RE.finditer(text):
            domain = m.group(1).lower().rstrip('.')
            if not re.match(r'^\d+\.\d+', domain):
                domains.add(domain)
        return domains

    def _check_domain(self, domain: str):
        # 1. Точные совпадения с известными читерскими доменами → danger
        for cheat_domain in _CHEAT_DOMAINS:
            if cheat_domain in domain:
                self.findings.append({
                    'level':   'danger',
                    'type':    'dns_cheat_domain',
                    'message': f'DNS: обращение к домену чита — {domain}',
                    'detail':  f'Домен: {domain}\nСигнатура: {cheat_domain}',
                })
                self._set_risk('danger')
                return

        # 2. Паттерны имён читов в доменном имени → suspicious
        for pattern in _NAME_PATTERNS:
            if pattern in domain:
                self.findings.append({
                    'level':   'suspicious',
                    'type':    'dns_suspicious_domain',
                    'message': f'DNS: подозрительный домен — {domain}',
                    'detail':  f'Домен: {domain}\nПаттерн: {pattern}',
                })
                self._set_risk('suspicious')
                return
