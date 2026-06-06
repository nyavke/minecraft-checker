"""
Path resolver that works both as a plain script and inside a PyInstaller EXE.

When PyInstaller unpacks a --onefile EXE it sets sys._MEIPASS to the temp dir
where all bundled data files are extracted.  In normal script mode the root is
just two levels above this file (project root).
"""
import sys
from pathlib import Path


def resource_path(rel: str) -> Path:
    """Return absolute Path to a bundled resource (relative to project root)."""
    if hasattr(sys, '_MEIPASS'):
        return Path(sys._MEIPASS) / rel
    return Path(__file__).parent.parent / rel
