"""
Entry point for the estimate-transfer Lambda.

Loads the real handler from estimate-transfer/app.py (directory name has a hyphen
and cannot be used as a Python module) so that when that module runs, its
__file__ is under /var/task/estimate-transfer/ and it can find sibling
estimate-storage via Path(__file__).parents[1] for DEFAULT_REGION.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_entry_path = Path(__file__).resolve().parents[0] / "estimate-transfer" / "app.py"
_spec = importlib.util.spec_from_file_location("estimate_transfer_app", _entry_path)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Unable to load estimate-transfer app module")
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

lambda_handler = _module.lambda_handler
