"""
Content Scanner — поиск по содержимому файлов (Everything-style deep scan).

Идея из фильтра Everything:
  utf8content:net/minecraft/util/math/AxisAlignedBB .exe | .dll | .jar

Сканирует подозрительные места хранения (TEMP, Downloads, корень C:\,
Program Files, скрытые папки AppData) на наличие файлов .exe/.dll/.jar/.zip,
которые содержат Minecraft-специфичные строки байткода Java.

Такой файл вне папки .minecraft — почти гарантированно чит-клиент,
загрузчик или патч даже если имя файла случайное.
"""

import os
import re
import json
import zipfile
from pathlib import Path
from detectors._resources import resource_path

with open(resource_path('signatures/cheats.json'), encoding='utf-8') as f:
    _SIGS = json.load(f)

# Строки Java-байткода, которые встречаются ТОЛЬКО в Minecraft-клиентах.
# Присутствие хотя бы одной из них в .exe/.dll/.jar вне .minecraft — красный флаг.
_MC_BYTECODE_MARKERS = [
    b'net/minecraft/util/math/AxisAlignedBB',      # ось AABB — хитбокс
    b'net/minecraft/client/Minecraft',              # главный класс клиента
    b'net/minecraft/entity/EntityLivingBase',       # базовый класс существ
    b'net/minecraft/client/gui/GuiScreen',          # GUI-экраны (чит-меню)
    b'net/minecraft/network/play/INetHandlerPlayServer',  # сетевой обработчик
    b'net/minecraft/client/renderer/entity/RenderLivingBase',  # рендер (ESP)
    b'net/minecraft/util/math/Vec3d',               # 3D-вектор
    b'net/minecraft/client/settings/GameSettings',  # настройки игры
    b'net/minecraft/world/World',                   # класс мира
]

# Строки из популярных обфускаторов читов — появляются в байткоде
_OBFUSCATOR_MARKERS = [
    b'allatori',              # Allatori обфускатор
    b'Zelix',                 # Zelix KlassMaster
    b'STRINGER',              # Stringer Java Obfuscator
    b'superblaubeere27',      # Skidfuscator
    b'SKIDFUSCATOR',          # Skidfuscator
    b'net.superblaubeere',    # Skidfuscator package
]

# Пути, которые считаются легитимными — файлы в них не алертим
_LEGIT_PATH_FRAGMENTS = {
    'minecraft', '.minecraft', 'versions', 'libraries',
    'jdk', 'jre', 'java', 'openjdk',
    'windows', 'system32', 'syswow64',
    'visual studio', 'vscode', 'android studio',
    'git', 'obs', 'obs-studio',
    'mozilla', 'google', 'chrome', 'firefox',
    'microsoft', 'dotnet', 'windowsapps',
    'steam', 'epic games', 'origin', 'gog galaxy',
    'discord', 'slack', 'telegram', 'whatsapp',
    'nvidia', 'amd', 'intel',
    'program files\\java', 'program files (x86)\\java',
    'eclipse', 'intellij', 'netbeans',
    'gradle', 'maven',
}

# Максимальный размер файла для сканирования содержимого (100 МБ)
_MAX_FILE_SIZE = 100 * 1024 * 1024

# Максимальное количество файлов для проверки (защита от зависания)
_MAX_FILES_TOTAL = 3000


def _is_legit_path(path_str: str) -> bool:
    pl = path_str.lower()
    return any(frag in pl for frag in _LEGIT_PATH_FRAGMENTS)


def _file_contains_mc_bytecode(path: Path) -> tuple[bool, str]:
    """
    Вернуть (True, marker) если файл содержит Minecraft-байткод.
    Для ZIP/JAR — проверяем .class-файлы внутри.
    Для бинарников — прямой поиск в сырых байтах.
    """
    try:
        if path.suffix.lower() in ('.jar', '.zip'):
            return _check_jar(path)
        else:
            return _check_binary(path)
    except (PermissionError, OSError):
        return False, ''


def _check_jar(path: Path) -> tuple[bool, str]:
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            names = zf.namelist()
            class_files = [n for n in names if n.endswith('.class')]
            if not class_files:
                return False, ''
            # Читаем первые 200 class-файлов — достаточно для детекции
            for name in class_files[:200]:
                try:
                    data = zf.read(name)
                except Exception:
                    continue
                for marker in _MC_BYTECODE_MARKERS:
                    if marker in data:
                        return True, marker.decode('ascii', errors='replace')
        return False, ''
    except (zipfile.BadZipFile, OSError, PermissionError):
        return False, ''


def _check_binary(path: Path) -> tuple[bool, str]:
    try:
        size = path.stat().st_size
        if size > _MAX_FILE_SIZE or size < 1024:
            return False, ''
        data = path.read_bytes()
        for marker in _MC_BYTECODE_MARKERS:
            if marker in data:
                return True, marker.decode('ascii', errors='replace')
        return False, ''
    except (OSError, PermissionError):
        return False, ''


def _file_contains_obfuscator(path: Path) -> tuple[bool, str]:
    """Дополнительная проверка на маркеры обфускаторов."""
    try:
        if path.suffix.lower() in ('.jar', '.zip'):
            try:
                with zipfile.ZipFile(path, 'r') as zf:
                    if 'META-INF/MANIFEST.MF' in zf.namelist():
                        mf = zf.read('META-INF/MANIFEST.MF').lower()
                        for marker in _OBFUSCATOR_MARKERS:
                            if marker.lower() in mf:
                                return True, marker.decode('ascii', errors='replace')
            except (zipfile.BadZipFile, OSError):
                pass
        else:
            size = path.stat().st_size
            if size < 1024 or size > _MAX_FILE_SIZE:
                return False, ''
            data = path.read_bytes()
            for marker in _OBFUSCATOR_MARKERS:
                if marker in data:
                    return True, marker.decode('ascii', errors='replace')
    except (OSError, PermissionError):
        pass
    return False, ''


class ContentScanner:
    """
    Глубокий поиск по содержимому файлов — аналог Everything-фильтра:
      utf8content:net/minecraft/util/math/AxisAlignedBB .exe | .dll | .jar

    Находит Minecraft-клиенты замаскированные под случайные имена,
    лежащие вне папки .minecraft.
    """

    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

        current = os.environ.get('USERNAME', '')
        if not username or username.lower() == current.lower():
            self.appdata      = Path(os.environ.get('APPDATA',      ''))
            self.localappdata = Path(os.environ.get('LOCALAPPDATA', ''))
            self.userprofile  = Path(os.environ.get('USERPROFILE',  ''))
        else:
            self.userprofile  = Path('C:/Users') / username
            self.appdata      = self.userprofile / 'AppData' / 'Roaming'
            self.localappdata = self.userprofile / 'AppData' / 'Local'

        self._scanned_count = 0

    def scan(self):
        self._scan_temp()
        self._scan_downloads()
        self._scan_appdata_hidden()
        self._scan_program_files()
        self._scan_disk_c_root()
        return {
            'name': 'Content Scanner (bytecode search)',
            'description': (
                'Глубокий поиск Minecraft-байткода в .exe/.dll/.jar файлах вне '
                '.minecraft — обнаруживает читы с рандомными именами '
                '(аналог Everything: utf8content:net/minecraft/util/math/AxisAlignedBB)'
            ),
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _check_file(self, path: Path):
        if self._scanned_count >= _MAX_FILES_TOTAL:
            return
        if _is_legit_path(str(path)):
            return

        self._scanned_count += 1

        hit, marker = _file_contains_mc_bytecode(path)
        if hit:
            try:
                size_kb = path.stat().st_size // 1024
            except OSError:
                size_kb = 0
            self.findings.append({
                'level': 'danger',
                'type': 'mc_bytecode_outside_minecraft',
                'message': (
                    f'Файл содержит Minecraft-байткод вне папки .minecraft: {path.name}'
                ),
                'detail': (
                    f'Путь: {path}\n'
                    f'Размер: {size_kb} КБ\n'
                    f'Маркер: {marker}\n'
                    f'Файл с таким содержимым вне .minecraft — признак чит-клиента'
                ),
            })
            self._set_risk('danger')
            return

        # Дополнительно — проверяем обфускаторы для .jar/.zip
        if path.suffix.lower() in ('.jar', '.zip'):
            hit_obf, marker_obf = _file_contains_obfuscator(path)
            if hit_obf:
                self.findings.append({
                    'level': 'suspicious',
                    'type': 'obfuscated_jar_outside_minecraft',
                    'message': (
                        f'JAR с признаком обфускации вне .minecraft: {path.name}'
                    ),
                    'detail': (
                        f'Путь: {path}\n'
                        f'Обфускатор: {marker_obf}\n'
                        f'Обфусцированные JAR вне .minecraft подозрительны'
                    ),
                })
                self._set_risk('suspicious')

    def _iter_files(self, root: Path, exts: set, max_depth: int = 3):
        """Рекурсивный обход папки до max_depth уровней."""
        if not root.exists() or self._scanned_count >= _MAX_FILES_TOTAL:
            return
        try:
            for entry in root.iterdir():
                if self._scanned_count >= _MAX_FILES_TOTAL:
                    return
                try:
                    if entry.is_file():
                        if entry.suffix.lower() in exts:
                            yield entry
                    elif entry.is_dir() and max_depth > 0:
                        yield from self._iter_files(entry, exts, max_depth - 1)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

    def _scan_temp(self):
        exts = {'.jar', '.zip', '.dll', '.exe'}
        for env_var in ('TEMP', 'TMP'):
            temp = Path(os.environ.get(env_var, ''))
            for f in self._iter_files(temp, exts, max_depth=2):
                self._check_file(f)

    def _scan_downloads(self):
        exts = {'.jar', '.zip', '.dll', '.exe'}
        downloads = self.userprofile / 'Downloads'
        for f in self._iter_files(downloads, exts, max_depth=3):
            self._check_file(f)

    def _scan_appdata_hidden(self):
        """
        Скрытые / нестандартные папки в AppData — типичные места
        для маскировки читов под легитимные программы.
        """
        exts = {'.jar', '.zip', '.dll'}
        legit_app_folders = {
            '.minecraft', 'minecraft', 'prismlauncher', 'multimc', 'tlauncher',
            'lunarclient', 'feather', 'curseforge', 'atlauncher', 'gdlauncher',
            'microsoft', 'mozilla', 'google', 'discord', 'slack',
            'code', 'vscode', 'npm', 'pip', 'python', 'java',
            'nvidia', 'amd', 'steam', 'epic games', 'spotify',
            'telegram', 'whatsapp', 'zoom', 'teams', 'skype',
        }

        for appdir in (self.appdata, self.localappdata):
            if not appdir.exists():
                continue
            try:
                for folder in appdir.iterdir():
                    if not folder.is_dir():
                        continue
                    fname = folder.name.lower().lstrip('.')
                    if fname in legit_app_folders:
                        continue
                    for f in self._iter_files(folder, exts, max_depth=2):
                        self._check_file(f)
            except (PermissionError, OSError):
                pass

    def _scan_program_files(self):
        """Корень Program Files / Program Files (x86) / ProgramData."""
        exts = {'.jar', '.dll'}
        roots = [
            Path('C:/ProgramData'),
            Path('C:/Users/Public'),
        ]
        for root in roots:
            for f in self._iter_files(root, exts, max_depth=3):
                self._check_file(f)

    def _scan_disk_c_root(self):
        """Прямые файлы и папки в корне C:\\ (глубина 2)."""
        exts = {'.jar', '.dll', '.exe', '.zip'}
        skip = {
            'windows', '$recycle.bin', 'system volume information',
            'recovery', '$winreagent', 'msocache', 'program files',
            'program files (x86)', 'programdata', 'users',
        }
        try:
            for entry in Path('C:/').iterdir():
                if entry.name.lower() in skip:
                    continue
                if entry.is_file() and entry.suffix.lower() in exts:
                    self._check_file(entry)
                elif entry.is_dir():
                    for f in self._iter_files(entry, exts, max_depth=2):
                        self._check_file(f)
        except (PermissionError, OSError):
            pass
