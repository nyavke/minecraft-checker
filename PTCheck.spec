# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for PTCheck.
Build command (run from project root):
    pyinstaller PTCheck.spec
Output: dist\PTCheck.exe
"""

from pathlib import Path

ROOT = Path(SPECPATH)

a = Analysis(
    [str(ROOT / 'scan.py')],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        # Signatures database
        (str(ROOT / 'signatures'), 'signatures'),
        # NirSoft tools (Windows-only external EXEs)
        (str(ROOT / 'executedprogramslist'), 'executedprogramslist'),
        (str(ROOT / 'recentfilesview'),      'recentfilesview'),
        (str(ROOT / 'usbdeview-x64'),        'usbdeview-x64'),
        (str(ROOT / 'regscanner'),           'regscanner'),
        # Everything search tool
        (str(ROOT / 'Everything.exe'),       '.'),
        (str(ROOT / 'Everything-1.5a.ini'),  '.'),
        (str(ROOT / 'Everything-1.5a.db'),   '.'),
        # Report templates (if any)
        (str(ROOT / 'report'),               'report'),
    ],
    hiddenimports=[
        'winreg',
        'psutil',
        'detectors._resources',
        'detectors.processes',
        'detectors.mods',
        'detectors.native',
        'detectors.network',
        'detectors.filesystem',
        'detectors.integrity',
        'detectors.strings_scan',
        'detectors.artifacts',
        'detectors.shellbag',
        'detectors.executedprograms',
        'detectors.dns_cache',
        'detectors.nirsoft_executed',
        'detectors.nirsoft_recent',
        'detectors.nirsoft_usb',
        'detectors.nirsoft_utils',
        'detectors.content_scan',
        'report.generator',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PTCheck',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # консольное приложение — отчёт выводится в терминал
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,        # запрашивать права администратора при запуске
)
