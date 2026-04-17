"""
Entry point for the storage-ls-web Lambda.

Loads the real handler from storage-ls-web/app.py (directory name has a hyphen
and cannot be used as a Python module).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_entry_path = Path(__file__).resolve().parents[0] / "storage-ls-web" / "app.py"
_spec = importlib.util.spec_from_file_location("storage_ls_web_app", _entry_path)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Unable to load storage-ls-web app module")
_module = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

lambda_handler = _module.lambda_handler
