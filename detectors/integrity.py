import os
import json
import hashlib
import zipfile
from pathlib import Path
from detectors._resources import resource_path

with open(resource_path('signatures/cheats.json'), encoding='utf-8') as f:
    SIGS = json.load(f)

# Официальные SHA1-хэши client.jar от Mojang (версия → sha1)
MOJANG_HASHES = {
    '1.8.9':  'b58de46d9a9fe3e718c006e31c9ce02ea4c6b73c',
    '1.12.2': '0f275bc1547d01fa5f56ba34bdc87d981ee12daf',
    '1.16.5': '37fd3c903861eeff3bc24b71eed48f828b5269c8',
    '1.17.1': 'f69c284232d7c7580bd89a5a4931c3581eae1378',
    '1.18.2': '5ff05ec10eeab25614de66bdce6a5b19d37c3c37',
    '1.19.4': '958928a560c9167687bea0f5448bda8f7940ff82',
    '1.20.1': 'a677c82a501a2a88b8d6d7e09f23d60c75f5cf71',
    '1.20.4': '5eecd95eb71cae90b96da76a5f91b0cfe5e4e8a5',
    '1.21':   '067a6a98d01a7038be3d0ed1e671dca5c5f64e70',
}


class IntegrityChecker:
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

    def scan(self):
        self._check_client_jars()
        self._check_launcher_profiles()
        return {
            'name': 'Проверка целостности клиента',
            'description': 'SHA1-хэши client.jar сравниваются с официальными хэшами Mojang',
            'findings': self.findings,
            'risk': self.risk,
        }

    def _set_risk(self, level):
        order = {'clean': 0, 'suspicious': 1, 'danger': 2}
        if order.get(level, 0) > order.get(self.risk, 0):
            self.risk = level

    def _sha1(self, path):
        h = hashlib.sha1()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    def _check_client_jars(self):
        # Все возможные расположения папки versions на Windows
        versions_candidates = [
            self.appdata      / '.minecraft' / 'versions',
            self.localappdata / 'Packages'   / 'Microsoft.MinecraftUWP_8wekyb3d8bbwe'
                              / 'LocalState' / 'games' / 'com.mojang' / 'versions',
        ]
        # PrismLauncher / MultiMC инстансы
        for launcher_dir in (
            self.appdata / 'PrismLauncher' / 'instances',
            self.appdata / 'MultiMC' / 'instances',
            self.appdata / '.tlauncher',
        ):
            if launcher_dir.exists():
                try:
                    for inst in launcher_dir.iterdir():
                        mc_ver = inst / '.minecraft' / 'versions'
                        if mc_ver.exists():
                            versions_candidates.append(mc_ver)
                        mc_ver2 = inst / 'minecraft' / 'versions'
                        if mc_ver2.exists():
                            versions_candidates.append(mc_ver2)
                except (OSError, PermissionError):
                    pass

        mc_base = None
        for cand in versions_candidates:
            if cand.exists():
                mc_base = cand
                break

        if mc_base is None:
            self.findings.append({
                'level': 'info',
                'type': 'no_versions_dir',
                'message': 'Папка versions не найдена',
                'detail': 'Проверка целостности client.jar пропущена',
            })
            return

        checked = 0
        for version_dir in mc_base.iterdir():
            if not version_dir.is_dir():
                continue
            version_name = version_dir.name

            client_jar = version_dir / f'{version_name}.jar'
            if not client_jar.exists():
                client_jar = version_dir / 'client.jar'
            if not client_jar.exists():
                continue

            checked += 1
            actual_hash = self._sha1(client_jar)
            if actual_hash is None:
                continue

            matched_version = None
            for ver, expected_hash in MOJANG_HASHES.items():
                if ver in version_name:
                    matched_version = ver
                    if actual_hash.lower() != expected_hash.lower():
                        self.findings.append({
                            'level': 'danger',
                            'type': 'client_jar_modified',
                            'message': f'client.jar для {version_name} изменён! Хэш не совпадает с Mojang',
                            'detail': f'Ожидался: {expected_hash}\nПолучен:  {actual_hash}',
                        })
                        self._set_risk('danger')
                    else:
                        self.findings.append({
                            'level': 'info',
                            'type': 'client_jar_ok',
                            'message': f'client.jar {version_name} — хэш совпадает с Mojang',
                            'detail': actual_hash,
                        })
                    break

            if matched_version is None:
                self.findings.append({
                    'level': 'info',
                    'type': 'client_jar_unknown_version',
                    'message': f'client.jar {version_name} — версия не в базе хэшей',
                    'detail': f'SHA1: {actual_hash}',
                })

        if checked == 0:
            self.findings.append({
                'level': 'info',
                'type': 'no_client_jars',
                'message': 'Файлы client.jar не найдены',
                'detail': '',
            })

    def _check_launcher_profiles(self):
        profiles_paths = [
            self.appdata / '.minecraft' / 'launcher_profiles.json',
            self.appdata / '.tlauncher' / 'legacy' / 'Minecraft' / 'game' / 'launcher_profiles.json',
        ]

        for profiles_path in profiles_paths:
            if not profiles_path.exists():
                continue
            try:
                data = json.loads(profiles_path.read_text(encoding='utf-8', errors='replace'))
                for profile_id, profile in data.get('profiles', {}).items():
                    jvm_args = profile.get('javaArgs', '')
                    if not jvm_args:
                        continue
                    suspicious = [
                        arg for arg in ('-javaagent', '-agentpath', '-agentlib')
                        if arg in jvm_args
                    ]
                    if suspicious:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'suspicious_jvm_in_profile',
                            'message': (
                                f'Подозрительные JVM-аргументы в профиле '
                                f'{profile.get("name", profile_id)}'
                            ),
                            'detail': jvm_args,
                        })
                        self._set_risk('danger')
            except (json.JSONDecodeError, KeyError, OSError):
                pass
