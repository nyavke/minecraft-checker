"""Shared helpers for NirSoft tool integration."""

import csv
import json
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from detectors._resources import resource_path

with open(resource_path('signatures/cheats.json'), encoding='utf-8') as f:
    _SIGS = json.load(f)

_PATTERNS = [p.lower() for p in _SIGS['process_names'] + _SIGS['mod_name_patterns']]

_DT_FORMATS = [
    '%Y-%m-%d %H:%M:%S',
    '%d/%m/%Y %H:%M:%S',
    '%m/%d/%Y %H:%M:%S',
    '%d.%m.%Y %H:%M:%S',
    '%d/%m/%Y %I:%M:%S %p',
    '%m/%d/%Y %I:%M:%S %p',
]


def contains_cheat(text: str) -> tuple[bool, str]:
    t = text.lower()
    for p in _PATTERNS:
        if p in t:
            return True, p
    return False, ''


def norm_dt(s: str) -> str:
    """Normalize NirSoft datetime string to YYYY-MM-DD HH:MM:SS."""
    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(s.strip(), fmt).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue
    return ''


def find_timestamp(row: list) -> str:
    for field in row:
        ts = norm_dt(field)
        if ts:
            return ts
    return ''


def run_nirsoft(tool_path: str) -> list:
    """Run NirSoft tool with /scomma, return parsed CSV rows."""
    tmp = tempfile.mktemp(suffix='.csv')
    try:
        subprocess.run([tool_path, '/scomma', tmp], capture_output=True, timeout=30)
        if not os.path.exists(tmp):
            return []
        for enc in ('utf-8', 'cp1251', 'cp866'):
            try:
                with open(tmp, encoding=enc) as f:
                    return [r for r in csv.reader(f) if any(r)]
            except (UnicodeDecodeError, csv.Error):
                continue
        return []
    except (subprocess.TimeoutExpired, OSError):
        return []
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
