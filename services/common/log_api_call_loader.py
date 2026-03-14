"""
Shared loader for optional API call logging.

This loader is intentionally best-effort and always falls back to a no-op
logger so logging failures never break Lambda initialization.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
from pathlib import Path
from typing import Any, Callable


def _noop_log_api_call(*args: Any, **kwargs: Any) -> None:
    del args, kwargs
    return None


def load_log_api_call(*, emit_warning: bool = False, logger: logging.Logger | None = None) -> Callable[..., None]:
    candidate_paths = (
        Path(__file__).resolve().parent / "api_call_logger.py",
        Path(__file__).resolve().parents[1] / "common" / "api_call_logger.py",
    )

    for module_path in candidate_paths:
        if not module_path.is_file():
            continue
        module_spec = importlib.util.spec_from_file_location("shared_api_call_logger", module_path)
        if module_spec is None or module_spec.loader is None:
            continue
        try:
            module = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(module)
        except Exception:
            continue
        log_api_call = getattr(module, "log_api_call", None)
        if callable(log_api_call):
            return log_api_call

    for module_name in ("common.api_call_logger", "api_call_logger"):
        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue
        log_api_call = getattr(module, "log_api_call", None)
        if callable(log_api_call):
            return log_api_call

    if emit_warning:
        (logger or logging.getLogger(__name__)).warning(
            "Shared api_call_logger module not found; falling back to no-op API call logging"
        )
    return _noop_log_api_call
