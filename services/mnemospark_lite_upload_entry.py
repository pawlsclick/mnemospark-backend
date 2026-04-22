"""
Entry point for the mnemospark-lite upload facade Lambda.

Loads the real handler from mnemospark-lite-upload/app.py (directory name has a hyphen
and cannot be used as a Python module) so that when that module runs, its
__file__ is under /var/task/mnemospark-lite-upload/.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_entry_path = Path(__file__).resolve().parents[0] / "mnemospark-lite-upload" / "app.py"
_spec = importlib.util.spec_from_file_location("mnemospark_lite_upload_app", _entry_path)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Unable to load mnemospark-lite-upload app module")
_module = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

lambda_handler = _module.lambda_handler

