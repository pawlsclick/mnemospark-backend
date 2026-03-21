"""
Shared API call logging helper.

Writes a structured API invocation record to DynamoDB and emits a JSON log line.
Logging is always best-effort and never raises to callers.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60
DEFAULT_TABLE_ENV = "API_CALLS_TABLE_NAME"
DEFAULT_TTL_ENV = "API_CALLS_TTL_SECONDS"
MAX_ERROR_MESSAGE_LENGTH = 1024
HEX_SIGNATURE_PATTERN = re.compile(r"0x[a-fA-F0-9]{130}")

_DYNAMODB_CLIENT: Any | None = None


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_request_context(event: dict[str, Any]) -> dict[str, Any]:
    request_context = event.get("requestContext")
    if isinstance(request_context, dict):
        return request_context
    return {}


def _extract_authorizer_wallet(event: dict[str, Any]) -> str | None:
    request_context = _extract_request_context(event)
    authorizer = request_context.get("authorizer")
    if not isinstance(authorizer, dict):
        return None

    candidates: list[Any] = [
        authorizer.get("walletAddress"),
        authorizer.get("wallet_address"),
    ]
    lambda_authorizer_context = authorizer.get("lambda")
    if isinstance(lambda_authorizer_context, dict):
        candidates.extend(
            [
                lambda_authorizer_context.get("walletAddress"),
                lambda_authorizer_context.get("wallet_address"),
            ]
        )

    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip().lower()
    return None


def _normalized_path(event: dict[str, Any], route: str | None = None) -> str:
    request_context = _extract_request_context(event)
    path_candidates = [
        route,
        event.get("resource"),
        request_context.get("resourcePath"),
        event.get("path"),
        request_context.get("path"),
    ]
    for candidate in path_candidates:
        if not isinstance(candidate, str):
            continue
        normalized = candidate.strip()
        if not normalized:
            continue
        normalized = normalized.split("?", 1)[0]
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if len(normalized) > 1:
            normalized = normalized.rstrip("/")
        return normalized
    return "/"


def _extract_http_method(event: dict[str, Any]) -> str:
    request_context = _extract_request_context(event)
    method_candidates = [event.get("httpMethod"), request_context.get("httpMethod")]
    for candidate in method_candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip().upper()
    return "UNKNOWN"


def _extract_api_gateway_request_id(event: dict[str, Any], context: Any) -> str:
    request_context = _extract_request_context(event)
    request_id_candidates = [
        request_context.get("requestId"),
        request_context.get("extendedRequestId"),
        getattr(context, "aws_request_id", None),
    ]
    for candidate in request_id_candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return str(uuid.uuid4())


def _parse_json_body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body")
    if body in (None, ""):
        return {}
    if isinstance(body, dict):
        return body
    if not isinstance(body, str):
        return {}
    try:
        payload = body
        if event.get("isBase64Encoded"):
            payload = base64.b64decode(payload).decode("utf-8")
        decoded = json.loads(payload)
        if isinstance(decoded, dict):
            return decoded
    except Exception:
        return {}
    return {}


def _extract_request_ids(event: dict[str, Any]) -> dict[str, Any]:
    body = _parse_json_body(event)
    query_params = event.get("queryStringParameters")
    if not isinstance(query_params, dict):
        query_params = {}

    merged = {}
    merged.update({k: v for k, v in query_params.items() if v is not None})
    merged.update({k: v for k, v in body.items() if v is not None})

    extracted: dict[str, Any] = {}
    for key in (
        "quote_id",
        "trans_id",
        "payment_id",
        "object_id",
        "object_key",
        "idempotency_key",
    ):
        value = merged.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            extracted[key] = str(value)
    return extracted


def _structured_log(level: int, event_name: str, **fields: Any) -> None:
    payload: dict[str, Any] = {"event": event_name}
    payload.update({key: value for key, value in fields.items() if value is not None})
    logger.log(level, json.dumps(payload, default=str, separators=(",", ":")))


def _sanitize_error_message(error_message: str | None) -> str | None:
    if error_message is None:
        return None
    sanitized = str(error_message).replace("\n", " ").replace("\r", " ").strip()
    sanitized = HEX_SIGNATURE_PATTERN.sub("[REDACTED_SIGNATURE]", sanitized)
    if len(sanitized) > MAX_ERROR_MESSAGE_LENGTH:
        return sanitized[:MAX_ERROR_MESSAGE_LENGTH]
    return sanitized


def _dynamodb_client() -> Any:
    global _DYNAMODB_CLIENT
    if _DYNAMODB_CLIENT is None:
        _DYNAMODB_CLIENT = boto3.client("dynamodb")
    return _DYNAMODB_CLIENT


def _build_dynamodb_item(
    *,
    request_id: str,
    timestamp: datetime,
    method: str,
    path: str,
    wallet_address: str | None,
    status_code: int,
    result: str,
    error_code: str | None,
    error_message: str | None,
    expires_at: int,
    extra_fields: dict[str, Any],
) -> dict[str, dict[str, str]]:
    item: dict[str, dict[str, str]] = {
        "request_id": {"S": request_id},
        "timestamp": {"S": timestamp.isoformat()},
        "method": {"S": method},
        "path": {"S": path},
        "status_code": {"N": str(status_code)},
        "result": {"S": result},
        "expires_at": {"N": str(expires_at)},
    }
    if wallet_address:
        item["wallet_address"] = {"S": wallet_address}
    if error_code:
        item["error_code"] = {"S": error_code}
    if error_message:
        item["error_message"] = {"S": error_message[:MAX_ERROR_MESSAGE_LENGTH]}

    for key, value in extra_fields.items():
        if value is None:
            continue
        if isinstance(value, str) and value.strip():
            item[key] = {"S": value.strip()}
        elif isinstance(value, bool):
            item[key] = {"BOOL": value}
        elif isinstance(value, int):
            item[key] = {"N": str(value)}
        elif isinstance(value, float):
            item[key] = {"N": str(value)}

    return item


def log_api_call(
    event: dict[str, Any],
    context: Any,
    route: str | None,
    result: str,
    *,
    status_code: int,
    error_code: str | None = None,
    error_message: str | None = None,
    table_name: str | None = None,
    **extra: Any,
) -> None:
    """
    Log API invocation metadata to DynamoDB and CloudWatch.

    This function is intentionally best-effort and swallows all internal errors.
    """
    try:
        now = datetime.now(timezone.utc)
        sanitized_error_message = _sanitize_error_message(error_message)
        request_id = _extract_api_gateway_request_id(event, context)
        method = _extract_http_method(event)
        path = _normalized_path(event, route=route)
        wallet_address = _extract_authorizer_wallet(event)
        lambda_name = getattr(context, "function_name", None)
        ttl_seconds = _safe_int(os.getenv(DEFAULT_TTL_ENV), DEFAULT_TTL_SECONDS)
        expires_at = int(time.time()) + max(ttl_seconds, 0)

        request_ids = _extract_request_ids(event)
        extra_fields: dict[str, Any] = {
            **request_ids,
            "lambda_name": lambda_name,
            **extra,
        }
        for reserved_key in ("request_id", "timestamp", "method", "path", "status_code", "result"):
            extra_fields.pop(reserved_key, None)

        payload = {
            "request_id": request_id,
            "timestamp": now.isoformat(),
            "method": method,
            "path": path,
            "wallet_address": wallet_address,
            "status_code": int(status_code),
            "result": result,
            "error_code": error_code,
            "error_message": sanitized_error_message,
            **{k: v for k, v in extra_fields.items() if v is not None},
        }

        resolved_table_name = (table_name or os.getenv(DEFAULT_TABLE_ENV) or "").strip()
        ddb_write_status = "skipped"

        if resolved_table_name:
            try:
                item = _build_dynamodb_item(
                    request_id=request_id,
                    timestamp=now,
                    method=method,
                    path=path,
                    wallet_address=wallet_address,
                    status_code=int(status_code),
                    result=result,
                    error_code=error_code,
                    error_message=sanitized_error_message,
                    expires_at=expires_at,
                    extra_fields=extra_fields,
                )
                _dynamodb_client().put_item(
                    TableName=resolved_table_name,
                    Item=item,
                )
                ddb_write_status = "ok"
            except Exception as exc:
                ddb_write_status = "failed"
                _structured_log(
                    logging.WARNING,
                    "api_call_log_write_failed",
                    request_id=request_id,
                    method=method,
                    path=path,
                    table_name=resolved_table_name,
                    error_type=type(exc).__name__,
                    error_message=_sanitize_error_message(str(exc)),
                )

        _structured_log(logging.INFO, "api_call_logged", ddb_write_status=ddb_write_status, **payload)
    except Exception as exc:
        _structured_log(
            logging.WARNING,
            "api_call_log_unexpected_failure",
            error_type=type(exc).__name__,
            error_message=_sanitize_error_message(str(exc)),
        )
