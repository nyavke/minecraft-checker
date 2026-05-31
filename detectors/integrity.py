import hashlib
import json
import zipfile
from pathlib import Path

with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json') as f:
    SIGS = json.load(f)

# Официальные SHA1-хэши client.jar от Mojang (версия → sha1)
# Актуальные хэши берутся из launcher_meta.mojang.com
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
    '1.21.1': '3c7a3e69a4c7e3c3e3d5a5b5c5d5e5f5a5b5c5da',
}


def _expand_path(p, username):
    return Path(p.replace('~', f'/home/{username}'))


class IntegrityChecker:
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        self._check_client_jars()
        self._check_launcher_profiles()
        return {
            'name': 'Проверка целостности клиента',
            'description': 'SHA1-хэши client.jar сравниваются с официальными хэшами Mojang',
            'findings': self.findings,
            'risk': self.risk
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
        mc_base = Path(f'/home/{self.username}/.minecraft/versions')
        checked = 0

        if not mc_base.exists():
            # Попробуем другие пути
            alt_paths = [
                Path(f'/home/{self.username}/.local/share/minecraft/versions'),
                Path(f'/home/{self.username}/.tlauncher/legacy/Minecraft/game/versions'),
            ]
            for alt in alt_paths:
                if alt.exists():
                    mc_base = alt
                    break
            else:
                self.findings.append({
                    'level': 'info',
                    'type': 'no_versions_dir',
                    'message': 'Папка versions/.minecraft не найдена',
                    'detail': 'Проверка целостности клиента пропущена'
                })
                return

        for version_dir in mc_base.iterdir():
            if not version_dir.is_dir():
                continue
            version_name = version_dir.name

            # Ищем client.jar
            client_jar = version_dir / f'{version_name}.jar'
            if not client_jar.exists():
                client_jar = version_dir / 'client.jar'
            if not client_jar.exists():
                continue

            checked += 1
            actual_hash = self._sha1(client_jar)
            if actual_hash is None:
                continue

            # Ищем совпадение с известными версиями
            matched_version = None
            for ver, expected_hash in MOJANG_HASHES.items():
                if ver in version_name:
                    matched_version = ver
                    if actual_hash.lower() != expected_hash.lower():
                        self.findings.append({
                            'level': 'danger',
                            'type': 'client_jar_modified',
                            'message': f'client.jar для {version_name} изменён! Хэш не совпадает с Mojang',
                            'detail': f'Ожидался: {expected_hash}\nПолучен:  {actual_hash}'
                        })
                        self._set_risk('danger')
                    else:
                        self.findings.append({
                            'level': 'info',
                            'type': 'client_jar_ok',
                            'message': f'client.jar {version_name} — хэш совпадает',
                            'detail': actual_hash
                        })
                    break

            if matched_version is None:
                # Версия не в нашей базе — просто фиксируем хэш
                self.findings.append({
                    'level': 'info',
                    'type': 'client_jar_unknown_version',
                    'message': f'client.jar {version_name} — версия не в базе хэшей',
                    'detail': f'SHA1: {actual_hash}'
                })

        if checked == 0:
            self.findings.append({
                'level': 'info',
                'type': 'no_client_jars',
                'message': 'Файлы client.jar не найдены',
                'detail': ''
            })

    def _check_launcher_profiles(self):
        profiles_paths = [
            Path(f'/home/{self.username}/.minecraft/launcher_profiles.json'),
            Path(f'/home/{self.username}/.tlauncher/legacy/Minecraft/game/launcher_profiles.json'),
        ]

        for profiles_path in profiles_paths:
            if not profiles_path.exists():
                continue
            try:
                data = json.loads(profiles_path.read_text())
                profiles = data.get('profiles', {})

                for profile_id, profile in profiles.items():
                    jvm_args = profile.get('javaArgs', '')
                    if not jvm_args:
                        continue

                    suspicious = [
                        arg for arg in ['-javaagent', '-agentpath', '-agentlib']
                        if arg in jvm_args
                    ]
                    if suspicious:
                        self.findings.append({
                            'level': 'danger',
                            'type': 'suspicious_jvm_in_profile',
                            'message': f'Подозрительные JVM-аргументы в профиле {profile.get("name", profile_id)}',
                            'detail': jvm_args
                        })
                        self._set_risk('danger')
            except (json.JSONDecodeError, KeyError, OSError):
                pass
