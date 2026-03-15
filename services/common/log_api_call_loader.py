"""
Shared loader for optional API call logging.

This loader is intentionally best-effort and always falls back to a no-op
logger so logging failures never break Lambda initialization.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
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
            sys.modules[module_spec.name] = module
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


def _build_log_api_call_result(
    log_api_call_getter: Callable[[], Callable[..., None]],
    route: str,
) -> Callable[..., None]:
    def _log_api_call_result(
        event: dict[str, Any],
        context: Any,
        *,
        status_code: int,
        result: str,
        error_code: str | None = None,
        error_message: str | None = None,
        **extra: Any,
    ) -> None:
        log_api_call_getter()(
            event=event,
            context=context,
            route=route,
            status_code=status_code,
            result=result,
            error_code=error_code,
            error_message=error_message,
            **extra,
        )

    return _log_api_call_result


def load_log_api_call_result(
    route: str,
    *,
    emit_warning: bool = False,
    logger: logging.Logger | None = None,
    log_api_call_getter: Callable[[], Callable[..., None]] | None = None,
) -> Callable[..., None]:
    if log_api_call_getter is None:
        loaded_log_api_call = load_log_api_call(emit_warning=emit_warning, logger=logger)

        def _loaded_log_api_call_getter() -> Callable[..., None]:
            return loaded_log_api_call

        log_api_call_getter = _loaded_log_api_call_getter

    return _build_log_api_call_result(
        log_api_call_getter,
        route,
    )
