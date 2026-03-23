"""
Lambda handler for GET/POST /storage/ls.

Stat mode (object_key present): head_object metadata:
{
  "success": true,
  "key": "<object-key>",
  "size_bytes": <size>,
  "bucket": "mnemospark-<wallet-hash>"
}

List mode (object_key omitted): list_objects_v2:
{
  "success": true,
  "list_mode": true,
  "bucket": "...",
  "objects": [{"key", "size_bytes", "last_modified"}, ...],
  "is_truncated": bool,
  "next_continuation_token": str | null
}
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

import boto3
from botocore.exceptions import ClientError

try:
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.storage_bucket_region import (
        BucketRegionMismatchError,
        enforce_requested_matches_bucket_home,
        resolve_bucket_home_region_from_head_bucket_error,
        resolve_bucket_home_region,
    )
except ModuleNotFoundError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.storage_bucket_region import (
        BucketRegionMismatchError,
        enforce_requested_matches_bucket_home,
        resolve_bucket_home_region_from_head_bucket_error,
        resolve_bucket_home_region,
    )


log_api_call = load_log_api_call()
_log_api_call_result = load_log_api_call_result("/storage/ls", log_api_call_getter=lambda: log_api_call)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

US_EAST_1_REGION = "us-" + "east-1"
DEFAULT_LOCATION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or US_EAST_1_REGION
DEFAULT_LIST_MAX_KEYS = 1000
LIST_MAX_KEYS_CAP = 1000

ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
BUCKET_NAME_MIN_LEN = 3
BUCKET_NAME_MAX_LEN = 63
BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
BUCKET_FORBIDDEN_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
BUCKET_FORBIDDEN_SUFFIXES = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
BUCKET_IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

NOT_FOUND_S3_ERROR_CODES = {
    "403",
    "404",
    "AccessDenied",
    "AllAccessDisabled",
    "NoSuchBucket",
    "NoSuchKey",
    "NotFound",
}
INVALID_LIST_ARGUMENT_S3_ERROR_CODES = {
    "InvalidArgument",
}


class BadRequestError(ValueError):
    """Raised when request validation fails."""


class ForbiddenError(ValueError):
    """Raised when authorizer wallet context is missing or mismatched."""


@dataclass(frozen=True)
class NotFoundError(Exception):
    error: str
    message: str


@dataclass(frozen=True)
class ParsedLsRequest:
    wallet_address: str
    location: str
    list_mode: bool
    object_key: str | None
    continuation_token: str | None
    max_keys: int
    prefix: str | None


def _log_event(level: int, event_name: str, **fields: Any) -> None:
    payload: dict[str, Any] = {"event": event_name}
    payload.update({key: value for key, value in fields.items() if value is not None})
    logger.log(level, json.dumps(payload, default=str, separators=(",", ":")))


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }


def _error_response(status_code: int, error: str, message: str, details: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {"error": error, "message": message}
    if details is not None:
        body["details"] = details
    return _response(status_code, body)


def _decode_event_body(event: dict[str, Any]) -> dict[str, Any]:
    raw_body = event.get("body")
    if raw_body in (None, ""):
        return {}

    if event.get("isBase64Encoded"):
        try:
            raw_body = base64.b64decode(raw_body).decode("utf-8")
        except Exception as exc:
            raise BadRequestError("body must be valid base64-encoded JSON") from exc

    try:
        decoded = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise BadRequestError("body must be valid JSON") from exc

    if not isinstance(decoded, dict):
        raise BadRequestError("JSON body must be an object")
    return decoded


def _collect_request_params(event: dict[str, Any]) -> dict[str, Any]:
    query_params = event.get("queryStringParameters") or {}
    if not isinstance(query_params, dict):
        raise BadRequestError("queryStringParameters must be an object")

    params = {key: value for key, value in query_params.items() if value is not None}
    params.update(_decode_event_body(event))
    return params


def _require_string_field(params: dict[str, Any], field_name: str) -> str:
    value = params.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise BadRequestError(f"{field_name} is required")
    return value.strip()


def _normalize_address(value: str, field_name: str) -> str:
    candidate = value.strip()
    if not ADDRESS_PATTERN.fullmatch(candidate):
        raise BadRequestError(f"{field_name} must be a 0x-prefixed 20-byte hex address")
    return f"0x{candidate[2:].lower()}"


def _extract_authorizer_wallet(event: dict[str, Any]) -> str | None:
    request_context = event.get("requestContext")
    if not isinstance(request_context, dict):
        return None
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
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        try:
            return _normalize_address(candidate, "authorizer walletAddress")
        except BadRequestError as exc:
            raise ForbiddenError("wallet authorization context is invalid") from exc

    return None


def _require_authorized_wallet(event: dict[str, Any], wallet_address: str) -> None:
    authorized_wallet = _extract_authorizer_wallet(event)
    if authorized_wallet is None:
        raise ForbiddenError("wallet authorization context is required")
    if authorized_wallet != wallet_address:
        raise ForbiddenError("wallet_address does not match authorized wallet")


def _validate_object_key(object_key: str) -> None:
    if not object_key or "/" in object_key or "\\" in object_key or object_key in {".", ".."}:
        raise BadRequestError("object_key must be a single path segment")


def _wallet_hash(wallet_address: str, length: int = 16) -> str:
    return hashlib.sha256(wallet_address.encode("utf-8")).hexdigest()[:length]


def _bucket_name(wallet_address: str) -> str:
    return f"mnemospark-{_wallet_hash(wallet_address)}"


def _validate_bucket_name(name: str) -> None:
    if not (BUCKET_NAME_MIN_LEN <= len(name) <= BUCKET_NAME_MAX_LEN):
        raise ValueError(f"Bucket name must be {BUCKET_NAME_MIN_LEN}-{BUCKET_NAME_MAX_LEN} characters")
    if not BUCKET_NAME_PATTERN.match(name):
        raise ValueError("Bucket name must use only lowercase letters, digits, dots, and hyphens")
    if name.startswith(BUCKET_FORBIDDEN_PREFIXES) or name.endswith(BUCKET_FORBIDDEN_SUFFIXES):
        raise ValueError("Bucket name uses a forbidden prefix or suffix")
    if BUCKET_IP_PATTERN.match(name):
        raise ValueError("Bucket name must not be formatted as an IP address")


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _assert_bucket_access(s3_client: Any, bucket_name: str, requested_location: str) -> None:
    try:
        head_resp = s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as exc:
        bucket_home = resolve_bucket_home_region_from_head_bucket_error(
            s3_client, bucket_name, exc.response
        )
        if bucket_home is None and _error_code(exc) in NOT_FOUND_S3_ERROR_CODES:
            raise NotFoundError("bucket_not_found", "Bucket not found for this wallet") from exc
        if bucket_home is not None:
            enforce_requested_matches_bucket_home(requested_location, bucket_home)
        raise
    bucket_home = resolve_bucket_home_region(s3_client, bucket_name, head_resp)
    enforce_requested_matches_bucket_home(requested_location, bucket_home)


def _get_object_size(s3_client: Any, bucket_name: str, object_key: str) -> int:
    try:
        response = s3_client.head_object(Bucket=bucket_name, Key=object_key)
    except ClientError as exc:
        if _error_code(exc) in NOT_FOUND_S3_ERROR_CODES:
            raise NotFoundError("object_not_found", f"Object not found: {object_key}") from exc
        raise
    return int(response.get("ContentLength", 0))


def _last_modified_iso(dt: Any) -> str | None:
    if dt is None or not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _parse_max_keys(params: dict[str, Any]) -> int:
    raw = params.get("max_keys")
    if raw in (None, ""):
        return DEFAULT_LIST_MAX_KEYS
    if isinstance(raw, bool):
        raise BadRequestError("max_keys must be an integer between 1 and 1000")
    if isinstance(raw, str):
        try:
            raw = int(raw.strip(), 10)
        except ValueError as exc:
            raise BadRequestError("max_keys must be an integer between 1 and 1000") from exc
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise BadRequestError("max_keys must be an integer between 1 and 1000")
    if raw < 1 or raw > LIST_MAX_KEYS_CAP:
        raise BadRequestError("max_keys must be an integer between 1 and 1000")
    return raw


def _parse_optional_string(params: dict[str, Any], field: str) -> str | None:
    raw = params.get(field)
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise BadRequestError(f"{field} must be a string")
    s = raw.strip()
    return s or None


def _list_objects(
    s3_client: Any,
    bucket_name: str,
    *,
    max_keys: int,
    continuation_token: str | None,
    prefix: str | None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"Bucket": bucket_name, "MaxKeys": max_keys}
    if continuation_token:
        kwargs["ContinuationToken"] = continuation_token
    if prefix:
        kwargs["Prefix"] = prefix
    try:
        return s3_client.list_objects_v2(**kwargs)
    except ClientError as exc:
        error_code = _error_code(exc)
        if error_code in NOT_FOUND_S3_ERROR_CODES:
            raise NotFoundError("bucket_not_found", "Bucket not found for this wallet") from exc
        if error_code in INVALID_LIST_ARGUMENT_S3_ERROR_CODES:
            raise BadRequestError("continuation_token is invalid or expired") from exc
        raise


def parse_input(event: dict[str, Any]) -> ParsedLsRequest:
    params = _collect_request_params(event)

    wallet_address = _normalize_address(_require_string_field(params, "wallet_address"), "wallet_address")
    object_key_raw = _parse_optional_string(params, "object_key")
    location = str(params.get("location") or params.get("region") or DEFAULT_LOCATION).strip() or DEFAULT_LOCATION

    if object_key_raw is not None:
        _validate_object_key(object_key_raw)
        return ParsedLsRequest(
            wallet_address=wallet_address,
            location=location,
            list_mode=False,
            object_key=object_key_raw,
            continuation_token=None,
            max_keys=DEFAULT_LIST_MAX_KEYS,
            prefix=None,
        )

    continuation_token = _parse_optional_string(params, "continuation_token")
    prefix = _parse_optional_string(params, "prefix")
    max_keys = _parse_max_keys(params)

    return ParsedLsRequest(
        wallet_address=wallet_address,
        location=location,
        list_mode=True,
        object_key=None,
        continuation_token=continuation_token,
        max_keys=max_keys,
        prefix=prefix,
    )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request: ParsedLsRequest | None = None
    bucket_name: str | None = None
    try:
        request = parse_input(event)
        _log_event(
            logging.INFO,
            "storage_ls_request_parsed",
            wallet_address=request.wallet_address,
            object_key=request.object_key,
            list_mode=request.list_mode,
            location=request.location,
        )
        _require_authorized_wallet(event, request.wallet_address)
        _log_event(
            logging.DEBUG,
            "storage_ls_authorized_wallet_confirmed",
            wallet_address=request.wallet_address,
        )
        s3_client = boto3.client("s3", region_name=request.location)
        bucket_name = _bucket_name(request.wallet_address)

        try:
            _validate_bucket_name(bucket_name)
        except ValueError as exc:
            raise BadRequestError(str(exc)) from exc

        _assert_bucket_access(s3_client, bucket_name, request.location)

        if request.list_mode:
            list_resp = _list_objects(
                s3_client,
                bucket_name,
                max_keys=request.max_keys,
                continuation_token=request.continuation_token,
                prefix=request.prefix,
            )
            contents = list_resp.get("Contents") or []
            objects_out: list[dict[str, Any]] = []
            for item in contents:
                key = item.get("Key")
                if not isinstance(key, str):
                    continue
                size_bytes = int(item.get("Size") or 0)
                lm = item.get("LastModified")
                objects_out.append(
                    {
                        "key": key,
                        "size_bytes": size_bytes,
                        "last_modified": _last_modified_iso(lm),
                    }
                )
            is_truncated = bool(list_resp.get("IsTruncated"))
            next_token = list_resp.get("NextContinuationToken")
            next_out: str | None = next_token if isinstance(next_token, str) else None

            _log_event(
                logging.INFO,
                "storage_ls_list_succeeded",
                wallet_address=request.wallet_address,
                bucket_name=bucket_name,
                object_count=len(objects_out),
                is_truncated=is_truncated,
            )
            _log_api_call_result(
                event,
                context,
                status_code=200,
                result="success",
                wallet_address=request.wallet_address,
                object_key=None,
                list_mode=True,
            )
            return _response(
                200,
                {
                    "success": True,
                    "list_mode": True,
                    "bucket": bucket_name,
                    "objects": objects_out,
                    "is_truncated": is_truncated,
                    "next_continuation_token": next_out,
                },
            )

        object_key = cast(str, request.object_key)
        object_size = _get_object_size(s3_client, bucket_name, object_key)
        _log_event(
            logging.INFO,
            "storage_ls_succeeded",
            wallet_address=request.wallet_address,
            object_key=object_key,
            bucket_name=bucket_name,
            size_bytes=object_size,
        )
        _log_api_call_result(
            event,
            context,
            status_code=200,
            result="success",
            wallet_address=request.wallet_address,
            object_key=object_key,
        )

        return _response(
            200,
            {
                "success": True,
                "key": object_key,
                "size_bytes": object_size,
                "bucket": bucket_name,
            },
        )
    except ForbiddenError as exc:
        _log_event(
            logging.WARNING,
            "storage_ls_forbidden",
            error_type=type(exc).__name__,
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        _log_api_call_result(
            event,
            context,
            status_code=403,
            result="forbidden",
            error_code="wallet_mismatch",
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(403, "forbidden", str(exc))
    except BucketRegionMismatchError as exc:
        _log_event(
            logging.WARNING,
            "storage_ls_bucket_region_mismatch",
            error_type=type(exc).__name__,
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
            requested_region=exc.requested_region,
            bucket_region=exc.bucket_home_region,
        )
        _log_api_call_result(
            event,
            context,
            status_code=400,
            result="bad_request",
            error_code="bucket_region_mismatch",
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(
            400,
            "bucket_region_mismatch",
            str(exc),
            details={
                "requested_region": exc.requested_region,
                "bucket_region": exc.bucket_home_region,
            },
        )
    except BadRequestError as exc:
        _log_event(
            logging.WARNING,
            "storage_ls_bad_request",
            error_type=type(exc).__name__,
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        _log_api_call_result(
            event,
            context,
            status_code=400,
            result="bad_request",
            error_code="bad_request",
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(400, "Bad request", str(exc))
    except NotFoundError as exc:
        _log_event(
            logging.WARNING,
            "storage_ls_not_found",
            error_type=type(exc).__name__,
            error_message=exc.message,
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
            bucket_name=bucket_name,
        )
        _log_api_call_result(
            event,
            context,
            status_code=404,
            result="not_found",
            error_code=exc.error,
            error_message=exc.message,
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(404, exc.error, exc.message)
    except Exception as exc:
        _log_event(
            logging.ERROR,
            "storage_ls_internal_error",
            error_type=type(exc).__name__,
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
            bucket_name=bucket_name,
        )
        _log_api_call_result(
            event,
            context,
            status_code=500,
            result="internal_error",
            error_code="internal_error",
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(500, "Internal error", str(exc))
