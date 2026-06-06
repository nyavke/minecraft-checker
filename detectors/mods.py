import os
import re
import json
import zipfile
from pathlib import Path


with open(Path(__file__).parent.parent / 'signatures' / 'cheats.json', encoding='utf-8') as f:
    SIGS = json.load(f)


def _get_user_paths(username):
    """Return (appdata, localappdata, userprofile) for the specified user."""
    current = os.environ.get('USERNAME', '')
    if not username or username.lower() == current.lower():
        appdata      = Path(os.environ.get('APPDATA',      ''))
        localappdata = Path(os.environ.get('LOCALAPPDATA', ''))
        userprofile  = Path(os.environ.get('USERPROFILE',  ''))
    else:
        userprofile  = Path('C:/Users') / username
        appdata      = userprofile / 'AppData' / 'Roaming'
        localappdata = userprofile / 'AppData' / 'Local'
    return appdata, localappdata, userprofile


def _find_minecraft_dirs(username):
    appdata, localappdata, userprofile = _get_user_paths(username)
    candidates = [
        appdata      / '.minecraft',
        appdata      / 'PrismLauncher' / 'instances',
        appdata      / 'prismlauncher' / 'instances',
        appdata      / 'MultiMC' / 'instances',
        appdata      / 'MultiMC5' / 'instances',
        appdata      / '.tlauncher',
        appdata      / 'feather-launcher',
        appdata      / 'ATLauncher' / 'instances',
        appdata      / 'GDLauncher Carbon' / 'instances',
        appdata      / 'gdlauncher' / 'instances',
        appdata      / 'FTBApp' / 'instances',
        appdata      / 'VoidLauncher' / 'instances',
        appdata      / 'com.modrinth.theseus' / 'profiles',
        localappdata / 'com.modrinth.theseus' / 'profiles',
        localappdata / 'Packages',          # Windows Store Minecraft (container)
        userprofile  / '.lunarclient' / 'offline',
        userprofile  / '.feather',
        userprofile  / 'curseforge' / 'minecraft' / 'Instances',
        userprofile  / 'AppData' / 'Roaming' / '.minecraft',
    ]
    # Also check paths from cheats.json (adapted for Windows)
    for p in SIGS.get('launcher_paths_win', []):
        resolved = Path(p
            .replace('%APPDATA%', str(appdata))
            .replace('%LOCALAPPDATA%', str(localappdata))
            .replace('%USERPROFILE%', str(userprofile))
        )
        candidates.append(resolved)

    return [p for p in candidates if p.exists()]


class ModScanner:
    def __init__(self, username):
        self.username = username
        self.findings = []
        self.risk = 'clean'

    def scan(self):
        self._find_and_scan_mods()
        self._scan_downloads()
        self._scan_labymod_addons()
        self._scan_minecraft_libraries()
        self._check_version_sizes()
        return {
            'name': 'Mod Scanner',
            'description': (
                'JAR-файлы: Minecraft dirs, Downloads, LabyMod addons, '
                'libraries/com/github, размеры версий'
            ),
            'findings': self.findings,
            'risk': self.risk,
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
                'message': 'Minecraft folders not found',
                'detail': (
                    'Checked: %APPDATA%\\.minecraft, PrismLauncher, MultiMC, '
                    'TLauncher, LunarClient, Feather, CurseForge, etc.'
                ),
            })
            return

        jar_files = []
        for mc_dir in mc_dirs:
            mods_dir = mc_dir / 'mods'
            if mods_dir.exists():
                jar_files.extend(mods_dir.glob('*.jar'))

            # PrismLauncher / MultiMC / CurseForge instances
            for pattern in ('*/mods/*.jar', '*/.minecraft/mods/*.jar', '*/minecraft/mods/*.jar'):
                try:
                    jar_files.extend(mc_dir.glob(pattern))
                except (OSError, PermissionError):
                    pass

        if not jar_files:
            self.findings.append({
                'level': 'info',
                'type': 'no_mods_found',
                'message': 'Mod files (.jar) not found',
                'detail': f'Checked {len(mc_dirs)} Minecraft folders',
            })
            return

        for jar_path in jar_files:
            self._scan_jar(jar_path)

    def _scan_jar(self, jar_path):
        name_lower = jar_path.name.lower()

        for pattern in SIGS['mod_name_patterns']:
            if pattern in name_lower:
                self.findings.append({
                    'level': 'danger',
                    'type': 'cheat_mod_name',
                    'message': f'Mod name matches known cheat: {jar_path.name}',
                    'detail': f'Pattern: {pattern} | Path: {jar_path}',
                })
                self._set_risk('danger')
                return

        self._check_jar_size(jar_path)

        try:
            with zipfile.ZipFile(jar_path, 'r') as zf:
                names = zf.namelist()

                if 'META-INF/MANIFEST.MF' in names:
                    manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
                    self._check_manifest(jar_path, manifest)

                class_files = [n for n in names if n.endswith('.class')]
                self._check_class_signatures(jar_path, class_files)
                self._check_obfuscation(jar_path, class_files)

        except (zipfile.BadZipFile, PermissionError, OSError) as e:
            self.findings.append({
                'level': 'suspicious',
                'type': 'jar_read_error',
                'message': f'Failed to read JAR: {jar_path.name}',
                'detail': str(e),
            })
            self._set_risk('suspicious')

    def _check_jar_size(self, jar_path):
        cheat_sizes = SIGS.get('cheat_jar_sizes_kb', {})
        if not cheat_sizes:
            return
        try:
            size_kb = str(jar_path.stat().st_size // 1024)
        except OSError:
            return
        if size_kb in cheat_sizes:
            cheat_name = cheat_sizes[size_kb]
            self.findings.append({
                'level': 'suspicious',
                'type': 'suspicious_jar_size',
                'message': f'Размер JAR ({size_kb} КБ) совпадает с известным читом: {jar_path.name}',
                'detail': f'Известные читы такого размера: {cheat_name} | Путь: {jar_path}',
            })
            self._set_risk('suspicious')

    def _check_manifest(self, jar_path, manifest):
        for key in SIGS['suspicious_manifest_keys']:
            if key + ':' in manifest:
                level = 'danger' if key in ('Agent-Class', 'Premain-Class') else 'suspicious'
                match = re.search(rf'{re.escape(key)}:\s*(.+)', manifest)
                value = match.group(1).strip() if match else 'unknown'
                self.findings.append({
                    'level': level,
                    'type': 'suspicious_manifest',
                    'message': f'Suspicious MANIFEST.MF in {jar_path.name}: {key}',
                    'detail': f'{key}: {value}',
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
                        'message': f'Detected {cheat_name} classes in {jar_path.name}',
                        'detail': f'Class: {class_path} | Signature: {pkg_sig}',
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
        if ratio > 0.6 and len(class_files) > 20:
            self.findings.append({
                'level': 'suspicious',
                'type': 'heavy_obfuscation',
                'message': f'Heavy code obfuscation in {jar_path.name} ({int(ratio*100)}% short names)',
                'detail': f'Total classes: {len(class_files)}, short names: {len(short_names)}',
            })
            self._set_risk('suspicious')

    # ─── Downloads folder ─────────────────────────────────────────────────────

    def _scan_downloads(self):
        """
        Scans the Downloads folder for JAR files.
        Checks the contents of each JAR regardless of filename —
        a random name (jasdIJHDiFuasdiu.jar) does not hide class signatures.
        """
        appdata = Path(os.environ.get('APPDATA', ''))
        userprofile = Path(os.environ.get('USERPROFILE', ''))
        current = os.environ.get('USERNAME', '')
        if self.username and self.username.lower() != current.lower():
            userprofile = Path('C:/Users') / self.username

        downloads = userprofile / 'Downloads'
        if not downloads.exists():
            return

        try:
            jar_files = list(downloads.glob('*.jar'))
        except (PermissionError, OSError):
            return

        if not jar_files:
            return

        for jar_path in jar_files:
            # First check the name
            name_lower = jar_path.name.lower()
            name_hit = any(p in name_lower for p in SIGS['mod_name_patterns'])

            # Scan JAR contents regardless
            before = len(self.findings)
            self._scan_jar(jar_path)
            content_hit = len(self.findings) > before

            # If name and contents both clean — JAR is unknown but in Downloads
            if not name_hit and not content_hit:
                # Check if this is actually a valid JAR?
                is_jar = False
                try:
                    with zipfile.ZipFile(jar_path, 'r') as zf:
                        is_jar = any(n.endswith('.class') for n in zf.namelist())
                except (zipfile.BadZipFile, OSError):
                    pass

                if is_jar:
                    # JAR with Java classes but no known signatures — suspicious
                    self.findings.append({
                        'level': 'suspicious',
                        'type': 'unknown_jar_in_downloads',
                        'message': f'Unknown JAR with Java classes in Downloads folder: {jar_path.name}',
                        'detail': (
                            f'Path: {jar_path}\n'
                            f'Name does not match known cheats, '
                            f'but contains compiled Java code — check manually'
                        ),
                    })
                    self._set_risk('suspicious')

    # ─── LabyMod addons ───────────────────────────────────────────────────────

    def _scan_labymod_addons(self):
        """
        Manual: LabyMod addons — suspicious sizes (9kb or 17kb),
        AutoReconnect with *.class, sprint_addon.jar.
        """
        appdata = Path(os.environ.get('APPDATA', ''))
        suspicious_sizes_kb = set(SIGS.get('labymod_suspicious_addon_sizes_kb', [9, 17]))
        known_cheat_addons  = set(SIGS.get('labymod_known_cheat_addons', []))

        for laby_dir_name in ('labymod-neo', 'LabyMod', 'labymod'):
            laby_dir = appdata / laby_dir_name
            if not laby_dir.exists():
                continue
            for addon_dir in laby_dir.glob('addons-*'):
                if not addon_dir.is_dir():
                    continue
                try:
                    for jar in addon_dir.glob('*.jar'):
                        size_kb = jar.stat().st_size // 1024

                        # Known cheat addon name
                        if jar.name in known_cheat_addons:
                            self.findings.append({
                                'level': 'danger',
                                'type': 'labymod_cheat_addon_name',
                                'message': f'LabyMod: known cheat addon — {jar.name}',
                                'detail': str(jar),
                            })
                            self._set_risk('danger')
                            continue

                        # Suspicious size
                        if size_kb in suspicious_sizes_kb:
                            # Check contents — any space-containing class or SpritingAddon
                            try:
                                with zipfile.ZipFile(jar, 'r') as zf:
                                    names = zf.namelist()
                                    has_space_class = any(' ' in n and n.endswith('.class') for n in names)
                                    has_spriting = any('SpritingAddon' in n or 'spriting' in n.lower() for n in names)
                                    if has_space_class or has_spriting:
                                        self.findings.append({
                                            'level': 'danger',
                                            'type': 'labymod_cheat_addon_content',
                                            'message': f'LabyMod: cheat addon (suspicious classes) — {jar.name}',
                                            'detail': f'Size: {size_kb} KB | Path: {jar}',
                                        })
                                        self._set_risk('danger')
                            except (zipfile.BadZipFile, OSError):
                                pass
                except (PermissionError, OSError):
                    pass

    # ─── .minecraft/libraries/com/github ─────────────────────────────────────

    def _scan_minecraft_libraries(self):
        """
        Manual: libraries/com/github should only contain the 'oshi' folder.
        Extra folders are a sign of a cheat (Impact hides there).
        """
        appdata = Path(os.environ.get('APPDATA', ''))
        mc_base = appdata / '.minecraft' / 'libraries' / 'com' / 'github'
        if not mc_base.exists():
            return

        legit = set(SIGS.get('minecraft_legit_library_folders', ['oshi']))
        try:
            for entry in mc_base.iterdir():
                if not entry.is_dir():
                    continue
                if entry.name.lower() not in legit:
                    self.findings.append({
                        'level': 'suspicious',
                        'type': 'suspicious_library_folder',
                        'message': f'.minecraft/libraries/com/github: unknown folder — {entry.name}',
                        'detail': (
                            f'Path: {entry}\n'
                            f'Only "oshi" is expected. This may be Impact or another cheat client.'
                        ),
                    })
                    self._set_risk('suspicious')
        except (PermissionError, OSError):
            pass

    # ─── .minecraft/versions size check ──────────────────────────────────────

    def _check_version_sizes(self):
        """
        Manual: the size of a clean client.jar is known for each version.
        A difference indicates a modified client.
        """
        appdata = Path(os.environ.get('APPDATA', ''))
        versions_dir = appdata / '.minecraft' / 'versions'
        if not versions_dir.exists():
            return

        clean_sizes = SIGS.get('version_clean_sizes_kb', {})
        if not clean_sizes:
            return

        try:
            for ver_dir in versions_dir.iterdir():
                if not ver_dir.is_dir():
                    continue
                ver_name = ver_dir.name
                client_jar = ver_dir / f'{ver_name}.jar'
                if not client_jar.exists():
                    client_jar = ver_dir / 'client.jar'
                if not client_jar.exists():
                    continue

                actual_kb = client_jar.stat().st_size // 1024
                matched_ver = None
                expected_kb = None
                for ver_key, size_kb in clean_sizes.items():
                    if ver_key in ver_name:
                        matched_ver = ver_key
                        expected_kb = size_kb
                        break

                if matched_ver is None:
                    continue

                diff_kb = abs(actual_kb - expected_kb)
                if diff_kb > 100:
                    self.findings.append({
                        'level': 'suspicious',
                        'type': 'client_jar_size_mismatch',
                        'message': (
                            f'client.jar size for {ver_name} differs from Mojang original '
                            f'by {diff_kb} KB'
                        ),
                        'detail': (
                            f'Expected: ~{expected_kb} KB | '
                            f'Actual: {actual_kb} KB | '
                            f'Path: {client_jar}'
                        ),
                    })
                    self._set_risk('suspicious')
        except (PermissionError, OSError):
            pass
