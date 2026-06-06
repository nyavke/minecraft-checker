"""
RecentFilesView scanner — недавно открытые файлы через NirSoft RecentFilesView.
Охватывает больше источников чем стандартный Recent-сканер.
"""

from detectors._resources import resource_path
from .nirsoft_utils import contains_cheat, find_timestamp, run_nirsoft

_TOOL = str(resource_path('recentfilesview/RecentFilesView.exe'))


class RecentFilesViewScanner:

    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk     = 'clean'

    def _set_risk(self, level: str):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def scan(self) -> dict:
        seen = set()
        for row in run_nirsoft(_TOOL):
            full_text = ' '.join(row)
            hit, pattern = contains_cheat(full_text)
            if not hit or pattern in seen:
                continue
            seen.add(pattern)

            path = row[1] if len(row) > 1 else (row[0] if row else '')
            ts   = find_timestamp(row)

            detail = f'Путь: {path}'
            if ts:
                detail += f'\nОткрыт: {ts}'

            self.findings.append({
                'level':   'danger',
                'type':    'nirsoft_recent_cheat',
                'message': f'Recent Files: "{pattern}"',
                'detail':  detail,
            })
            self._set_risk('danger')

        return {
            'name':        'Recent Files View',
            'description': 'Недавно открытые файлы со всех источников Windows — через NirSoft',
            'findings':    self.findings,
            'risk':        self.risk,
        }
