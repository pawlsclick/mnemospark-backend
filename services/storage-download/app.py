"""
Lambda handler for GET/POST /storage/download.

Flow:
1. Parse request query/body for wallet_address, object_key, optional location.
2. Validate wallet + object key and resolve wallet bucket.
3. Ensure bucket/object exist and return a short-lived presigned S3 GET URL.
"""

from __future__ import annotations

import json
import logging
import os
from functools import partial
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError

try:
    from common.http_response_headers import rest_api_json_headers
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.request_log_utils import (
        build_log_event,
        request_id,
        request_method,
        request_path,
        sanitize_error_message,
    )
    from common.storage_wallet_s3 import (
        BadRequestError,
        ForbiddenError,
        bucket_name_from_wallet,
        coerce_presigned_ttl_seconds,
        decode_json_event_body,
        normalize_wallet_address,
        require_authorized_wallet_match,
        s3_not_found_for_download,
        validate_object_key_single_segment,
    )
except ModuleNotFoundError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.http_response_headers import rest_api_json_headers
    from common.log_api_call_loader import load_log_api_call, load_log_api_call_result
    from common.request_log_utils import (
        build_log_event,
        request_id,
        request_method,
        request_path,
        sanitize_error_message,
    )
    from common.storage_wallet_s3 import (
        BadRequestError,
        ForbiddenError,
        bucket_name_from_wallet,
        coerce_presigned_ttl_seconds,
        decode_json_event_body,
        normalize_wallet_address,
        require_authorized_wallet_match,
        s3_not_found_for_download,
        validate_object_key_single_segment,
    )


log_api_call = load_log_api_call()
_log_api_call_result = load_log_api_call_result("/storage/download", log_api_call_getter=lambda: log_api_call)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
_log_event = build_log_event(logger)
_request_id = request_id
_request_method = request_method
_request_path = partial(request_path, default_path="/storage/download")
_sanitize_error_message = sanitize_error_message

US_EAST_1_REGION = "us-" + "east-1"
DEFAULT_LOCATION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or US_EAST_1_REGION
DEFAULT_PRESIGNED_TTL_SECONDS = int(os.environ.get("STORAGE_DOWNLOAD_URL_TTL_SECONDS", "300"))

class MethodNotAllowedError(ValueError):
    """Raised when an unsupported HTTP method is provided."""


@dataclass(frozen=True)
class NotFoundError(Exception):
    error: str
    message: str
    details: Any = None


@dataclass(frozen=True)
class ParsedDownloadRequest:
    wallet_address: str
    object_key: str
    location: str
    expires_in_seconds: int


def _response(status_code: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    merged_headers = rest_api_json_headers()
    if headers:
        merged_headers.update(headers)
    return {
        "statusCode": status_code,
        "headers": merged_headers,
        "body": json.dumps(body, default=str),
    }


def _error_response(status_code: int, error: str, message: str, details: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {"error": error, "message": message}
    if details is not None:
        body["details"] = details
    return _response(status_code, body)


def _collect_request_params(event: dict[str, Any]) -> dict[str, Any]:
    query_params = event.get("queryStringParameters") or {}
    if not isinstance(query_params, dict):
        raise BadRequestError("queryStringParameters must be an object")

    params = {key: value for key, value in query_params.items() if value is not None}
    params.update(decode_json_event_body(event))
    return params


def _require_string_field(params: dict[str, Any], *field_names: str) -> str:
    for field_name in field_names:
        value = params.get(field_name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise BadRequestError(f"{field_names[0]} is required")


def _error_message(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Message", str(exc)))


_bucket_name = bucket_name_from_wallet
_normalize_address = normalize_wallet_address
_decode_event_body = decode_json_event_body


def parse_input(event: dict[str, Any]) -> ParsedDownloadRequest:
    method = str(event.get("httpMethod") or "GET").upper()
    if method not in {"GET", "POST"}:
        raise MethodNotAllowedError("Only GET and POST are supported")

    params = _collect_request_params(event)

    wallet_address = normalize_wallet_address(
        _require_string_field(params, "wallet_address", "walletAddress"),
        "wallet_address",
    )
    object_key = validate_object_key_single_segment(
        _require_string_field(params, "object_key", "objectKey"),
    )
    location = str(params.get("location") or params.get("region") or DEFAULT_LOCATION).strip() or DEFAULT_LOCATION
    expires_in_seconds = coerce_presigned_ttl_seconds(
        params.get("expires_in_seconds"),
        default=DEFAULT_PRESIGNED_TTL_SECONDS,
    )

    return ParsedDownloadRequest(
        wallet_address=wallet_address,
        object_key=object_key,
        location=location,
        expires_in_seconds=expires_in_seconds,
    )


def generate_download_url(request: ParsedDownloadRequest, s3_client: Any | None = None) -> dict[str, Any]:
    s3_client = s3_client or boto3.client("s3", region_name=request.location)
    bucket_name = bucket_name_from_wallet(request.wallet_address)

    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if s3_not_found_for_download(exc):
            raise NotFoundError(
                error="bucket_not_found",
                message="Bucket not found for this wallet.",
                details=_error_message(exc),
            ) from exc
        raise

    try:
        s3_client.head_object(Bucket=bucket_name, Key=request.object_key)
    except ClientError as exc:
        if s3_not_found_for_download(exc):
            raise NotFoundError(
                error="object_not_found",
                message=f"Object not found: {request.object_key}.",
                details=_error_message(exc),
            ) from exc
        raise

    download_url = s3_client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket_name, "Key": request.object_key},
        ExpiresIn=request.expires_in_seconds,
        HttpMethod="GET",
    )
    return {
        "download_url": download_url,
        "object_key": request.object_key,
        "expires_in_seconds": request.expires_in_seconds,
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request: ParsedDownloadRequest | None = None
    try:
        request = parse_input(event)
        _log_event(
            logging.INFO,
            "storage_download_request_parsed",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            wallet_address=request.wallet_address,
            object_key=request.object_key,
        )
        require_authorized_wallet_match(event, request.wallet_address)
        response_body = generate_download_url(request)
        _log_event(
            logging.INFO,
            "storage_download_succeeded",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            status=200,
            wallet_address=request.wallet_address,
            object_key=request.object_key,
        )
        _log_api_call_result(
            event,
            context,
            status_code=200,
            result="success",
            wallet_address=request.wallet_address,
            object_key=request.object_key,
        )
        return _response(200, response_body)
    except ForbiddenError as exc:
        _log_event(
            logging.WARNING,
            "storage_download_forbidden",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            status=403,
            error_code="wallet_mismatch",
            error_message=_sanitize_error_message(str(exc)),
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
    except BadRequestError as exc:
        _log_event(
            logging.WARNING,
            "storage_download_bad_request",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            status=400,
            error_code="bad_request",
            error_message=_sanitize_error_message(str(exc)),
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
    except MethodNotAllowedError as exc:
        _log_event(
            logging.WARNING,
            "storage_download_method_not_allowed",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            status=405,
            error_code="method_not_allowed",
            error_message=_sanitize_error_message(str(exc)),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        _log_api_call_result(
            event,
            context,
            status_code=405,
            result="method_not_allowed",
            error_code="method_not_allowed",
            error_message=str(exc),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
        )
        return _error_response(405, "method_not_allowed", str(exc))
    except NotFoundError as exc:
        _log_event(
            logging.WARNING,
            "storage_download_not_found",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            status=404,
            error_code=exc.error,
            error_message=_sanitize_error_message(exc.message),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
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
        return _error_response(404, exc.error, exc.message, details=exc.details)
    except Exception as exc:
        _log_event(
            logging.ERROR,
            "storage_download_internal_error",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event),
            status=500,
            error_code="internal_error",
            error_message=_sanitize_error_message(str(exc)),
            wallet_address=request.wallet_address if request else None,
            object_key=request.object_key if request else None,
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
