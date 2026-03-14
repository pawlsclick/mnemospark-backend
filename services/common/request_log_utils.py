"""
Shared request/log utilities for service handlers.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from common.api_call_logger import _sanitize_error_message as _canonical_sanitize_error_message


def build_log_event(logger: logging.Logger) -> Callable[..., None]:
    def _log_event(level: int, event_name: str, **fields: Any) -> None:
        payload: dict[str, Any] = {"event": event_name}
        payload.update({key: value for key, value in fields.items() if value is not None})
        logger.log(level, json.dumps(payload, default=str, separators=(",", ":")))

    return _log_event


def request_context(event: dict[str, Any]) -> dict[str, Any]:
    request_ctx = event.get("requestContext")
    if isinstance(request_ctx, dict):
        return request_ctx
    return {}


def request_id(event: dict[str, Any], context: Any) -> str | None:
    request_ctx = request_context(event)
    candidates = (
        request_ctx.get("requestId"),
        request_ctx.get("extendedRequestId"),
        getattr(context, "aws_request_id", None),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def request_method(event: dict[str, Any]) -> str:
    request_ctx = request_context(event)
    candidates = (
        event.get("httpMethod"),
        request_ctx.get("httpMethod"),
        (request_ctx.get("http") or {}).get("method") if isinstance(request_ctx.get("http"), dict) else None,
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip().upper()
    return "UNKNOWN"


def request_path(event: dict[str, Any], default_path: str) -> str:
    request_ctx = request_context(event)
    candidates = (
        event.get("resource"),
        request_ctx.get("resourcePath"),
        event.get("path"),
        request_ctx.get("path"),
        event.get("rawPath"),
        default_path,
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            path = candidate.strip().split("?", 1)[0]
            if not path.startswith("/"):
                path = f"/{path}"
            return path
    return default_path


def sanitize_error_message(error_message: str | None, *, max_length: int | None = None) -> str | None:
    sanitized = _canonical_sanitize_error_message(error_message)
    if sanitized is None or max_length is None or len(sanitized) <= max_length:
        return sanitized
    return sanitized[:max_length]
