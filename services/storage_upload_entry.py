"""
Entry point for the storage-upload Lambda functions.

Loads the real handlers from storage-upload/app.py (directory name has a hyphen
and cannot be used as a Python module) so that when that module runs, its
__file__ is under /var/task/storage-upload/.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_entry_path = Path(__file__).resolve().parents[0] / "storage-upload" / "app.py"
_spec = importlib.util.spec_from_file_location("storage_upload_app", _entry_path)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Unable to load storage-upload app module")
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

lambda_handler = _module.lambda_handler
confirm_upload_handler = _module.confirm_upload_handler
