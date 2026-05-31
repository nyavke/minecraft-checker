import os
import re
import json
import hashlib
import zipfile
from pathlib import Path

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)


def _expand_path(p, username):
    return Path(p.replace('~', f'/home/{username}'))


def _find_minecraft_dirs(username):
    dirs = []
    for pattern in SIGS['launcher_paths']:
        p = _expand_path(pattern, username)
        if p.exists():
            dirs.append(p)
    return dirs


class ModScanner:
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        self._find_and_scan_mods()
        return {
            'name': 'Сканер модов',
            'description': 'JAR-файлы модов: имена, классы внутри архива, MANIFEST.MF, обфускация',
            'findings': self.findings,
            'risk': self.risk
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _find_and_scan_mods(self):
        mc_dirs = _find_minecraft_dirs(self.username)

        if not mc_dirs:
            self.findings.append({
                'level': 'info',
                'type': 'no_minecraft_dirs',
                'message': 'Папки Minecraft не найдены',
                'detail': 'Проверены стандартные пути: ~/.minecraft, PrismLauncher, MultiMC, TLauncher и др.'
            })
            return

        jar_files = []
        for mc_dir in mc_dirs:
            # Прямая папка mods
            mods_dir = mc_dir / 'mods'
            if mods_dir.exists():
                jar_files.extend(mods_dir.glob('*.jar'))

            # Инстансы MultiMC / PrismLauncher
            for instance_mods in mc_dir.glob('*/mods/*.jar'):
                jar_files.append(instance_mods)
            for instance_mods in mc_dir.glob('*/.minecraft/mods/*.jar'):
                jar_files.append(instance_mods)

        if not jar_files:
            self.findings.append({
                'level': 'info',
                'type': 'no_mods_found',
                'message': 'Файлы модов (.jar) не найдены',
                'detail': f'Проверено {len(mc_dirs)} папок Minecraft'
            })
            return

        for jar_path in jar_files:
            self._scan_jar(jar_path)

    def _scan_jar(self, jar_path):
        name_lower = jar_path.name.lower()

        # Проверка имени по сигнатурам
        for pattern in SIGS['mod_name_patterns']:
            if pattern in name_lower:
                self.findings.append({
                    'level': 'danger',
                    'type': 'cheat_mod_name',
                    'message': f'Имя мода совпадает с известным читом: {jar_path.name}',
                    'detail': f'Паттерн: {pattern} | Путь: {jar_path}'
                })
                self._set_risk('danger')
                return

        try:
            with zipfile.ZipFile(jar_path, 'r') as zf:
                names = zf.namelist()

                # Проверка MANIFEST.MF
                if 'META-INF/MANIFEST.MF' in names:
                    manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
                    self._check_manifest(jar_path, manifest)

                # Проверка классов по сигнатурам пакетов
                class_files = [n for n in names if n.endswith('.class')]
                self._check_class_signatures(jar_path, class_files)

                # Проверка на обфускацию (слишком много однобуквенных классов)
                self._check_obfuscation(jar_path, class_files)

        except (zipfile.BadZipFile, PermissionError, OSError) as e:
            self.findings.append({
                'level': 'suspicious',
                'type': 'jar_read_error',
                'message': f'Не удалось прочитать JAR: {jar_path.name}',
                'detail': str(e)
            })
            self._set_risk('suspicious')

    def _check_manifest(self, jar_path, manifest):
        for key in SIGS['suspicious_manifest_keys']:
            if key + ':' in manifest:
                level = 'danger' if key in ('Agent-Class', 'Premain-Class') else 'suspicious'
                # Извлечь значение
                match = re.search(rf'{re.escape(key)}:\s*(.+)', manifest)
                value = match.group(1).strip() if match else 'unknown'
                self.findings.append({
                    'level': level,
                    'type': 'suspicious_manifest',
                    'message': f'Подозрительный MANIFEST.MF в {jar_path.name}: {key}',
                    'detail': f'{key}: {value}'
                })
                self._set_risk(level)

    def _check_class_signatures(self, jar_path, class_files):
        for class_file in class_files:
            class_path = class_file.replace('/', '.').removesuffix('.class')
            for pkg_sig, cheat_name in SIGS['java_package_signatures'].items():
                if class_path.startswith(pkg_sig):
                    self.findings.append({
                        'level': 'danger',
                        'type': 'cheat_class_signature',
                        'message': f'Обнаружены классы {cheat_name} в {jar_path.name}',
                        'detail': f'Класс: {class_path} | Сигнатура: {pkg_sig}'
                    })
                    self._set_risk('danger')
                    return

    def _check_obfuscation(self, jar_path, class_files):
        if not class_files:
            return
        short_names = [
            Path(c).stem for c in class_files
            if len(Path(c).stem) <= 2 and Path(c).stem.isalpha()
        ]
        ratio = len(short_names) / len(class_files)
        # Если более 60% классов имеют имена из 1-2 символов — подозрительная обфускация
        if ratio > 0.6 and len(class_files) > 20:
            self.findings.append({
                'level': 'suspicious',
                'type': 'heavy_obfuscation',
                'message': f'Сильная обфускация кода в {jar_path.name} ({int(ratio*100)}% коротких имён)',
                'detail': f'Всего классов: {len(class_files)}, коротких имён: {len(short_names)}'
            })
            self._set_risk('suspicious')
