"""
ExecutedProgramsList scanner — история запусков через NirSoft ExecutedProgramsList.
Покрывает ShimCache, UserAssist, Prefetch, BAM одновременно.
"""

from detectors._resources import resource_path
from .nirsoft_utils import contains_cheat, find_timestamp, run_nirsoft

_TOOL = str(resource_path('executedprogramslist/ExecutedProgramsList.exe'))


class ExecutedProgramsListScanner:

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
                detail += f'\nПоследний запуск: {ts}'

            # Источник обычно в 7-й колонке (ShimCache / UserAssist / Prefetch / BAM)
            source = row[7].strip() if len(row) > 7 else ''
            if source:
                detail += f'\nИсточник: {source}'

            self.findings.append({
                'level':   'danger',
                'type':    'nirsoft_executed_cheat',
                'message': f'Executed Programs: "{pattern}"',
                'detail':  detail,
            })
            self._set_risk('danger')

        return {
            'name':        'Executed Programs List',
            'description': 'История запусков: ShimCache, UserAssist, Prefetch, BAM — через NirSoft',
            'findings':    self.findings,
            'risk':        self.risk,
        }
