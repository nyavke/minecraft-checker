"""
USBDeview scanner — история подключённых USB устройств через NirSoft USBDeview.
Ловит USB-носители с именами читов и устройства, подключавшиеся в момент установки чита.
"""

from pathlib import Path
from .nirsoft_utils import contains_cheat, norm_dt, run_nirsoft

_TOOL = str(Path(__file__).parent.parent / 'usbdeview-x64' / 'USBDeview.exe')


class USBDeviewScanner:

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
            if not row:
                continue

            # Колонки USBDeview: 0=Device Name, 1=Description, 4=Drive Letter,
            # 5=Serial Number, 6=Created Date, 7=Last Plug/Unplug Date
            device_name = row[0] if len(row) > 0 else ''
            description = row[1] if len(row) > 1 else ''
            drive       = row[4] if len(row) > 4 else ''
            serial      = row[5] if len(row) > 5 else ''
            last_plug   = norm_dt(row[7]) if len(row) > 7 else ''

            check_text = f'{device_name} {description}'
            hit, pattern = contains_cheat(check_text)
            if not hit or pattern in seen:
                continue
            seen.add(pattern)

            detail_parts = [f'Устройство: {device_name}']
            if description:
                detail_parts.append(f'Описание: {description}')
            if drive:
                detail_parts.append(f'Буква диска: {drive}')
            if serial:
                detail_parts.append(f'Серийный номер: {serial}')
            if last_plug:
                detail_parts.append(f'Последнее подключение: {last_plug}')

            self.findings.append({
                'level':   'danger',
                'type':    'nirsoft_usb_cheat',
                'message': f'USB: устройство с именем чита — "{pattern}"',
                'detail':  '\n'.join(detail_parts),
            })
            self._set_risk('danger')

        return {
            'name':        'USB History (USBDeview)',
            'description': 'История USB устройств — флешки с именами читов — через NirSoft',
            'findings':    self.findings,
            'risk':        self.risk,
        }
