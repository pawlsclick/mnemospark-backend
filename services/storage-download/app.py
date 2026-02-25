"""
Lambda handler for GET/POST /storage/download.

Flow:
1. Parse request query/body for wallet_address, object_key, optional location.
2. Validate wallet + object key and resolve wallet bucket.
3. Ensure bucket/object exist and return a short-lived presigned S3 GET URL.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError

US_EAST_1_REGION = "us-" + "east-1"
DEFAULT_LOCATION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or US_EAST_1_REGION
DEFAULT_PRESIGNED_TTL_SECONDS = int(os.environ.get("STORAGE_DOWNLOAD_URL_TTL_SECONDS", "300"))

ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
NOT_FOUND_ERROR_CODES = {"404", "NotFound", "NoSuchBucket", "NoSuchKey"}


class BadRequestError(ValueError):
    """Raised when request validation fails."""


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
    merged_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
    }
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


def _require_string_field(params: dict[str, Any], *field_names: str) -> str:
    for field_name in field_names:
        value = params.get(field_name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise BadRequestError(f"{field_names[0]} is required")


def _normalize_address(value: str, field_name: str) -> str:
    candidate = value.strip()
    if not ADDRESS_PATTERN.fullmatch(candidate):
        raise BadRequestError(f"{field_name} must be a 0x-prefixed 20-byte hex address")
    return f"0x{candidate[2:].lower()}"


def _validate_object_key(object_key: str) -> str:
    object_key = object_key.strip()
    if not object_key or "/" in object_key or "\\" in object_key or object_key in {".", ".."}:
        raise BadRequestError("object_key must be a single path segment")
    return object_key


def _coerce_expires_in_seconds(value: Any) -> int:
    if value is None or value == "":
        return DEFAULT_PRESIGNED_TTL_SECONDS
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise BadRequestError("expires_in_seconds must be an integer") from exc
    if parsed < 1 or parsed > 3600:
        raise BadRequestError("expires_in_seconds must be between 1 and 3600")
    return parsed


def _wallet_hash(wallet_address: str, length: int = 16) -> str:
    return hashlib.sha256(wallet_address.encode("utf-8")).hexdigest()[:length]


def _bucket_name(wallet_address: str) -> str:
    return f"mnemospark-{_wallet_hash(wallet_address)}"


def _error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def _error_message(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Message", str(exc)))


def _is_not_found_error(exc: ClientError) -> bool:
    return _error_code(exc) in NOT_FOUND_ERROR_CODES


def parse_input(event: dict[str, Any]) -> ParsedDownloadRequest:
    method = str(event.get("httpMethod") or "GET").upper()
    if method not in {"GET", "POST"}:
        raise MethodNotAllowedError("Only GET and POST are supported")

    params = _collect_request_params(event)

    wallet_address = _normalize_address(
        _require_string_field(params, "wallet_address", "walletAddress"),
        "wallet_address",
    )
    object_key = _validate_object_key(
        _require_string_field(params, "object_key", "objectKey"),
    )
    location = str(params.get("location") or params.get("region") or DEFAULT_LOCATION).strip() or DEFAULT_LOCATION
    expires_in_seconds = _coerce_expires_in_seconds(params.get("expires_in_seconds"))

    return ParsedDownloadRequest(
        wallet_address=wallet_address,
        object_key=object_key,
        location=location,
        expires_in_seconds=expires_in_seconds,
    )


def generate_download_url(request: ParsedDownloadRequest, s3_client: Any | None = None) -> dict[str, Any]:
    s3_client = s3_client or boto3.client("s3", region_name=request.location)
    bucket_name = _bucket_name(request.wallet_address)

    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if _is_not_found_error(exc):
            raise NotFoundError(
                error="bucket_not_found",
                message="Bucket not found for this wallet.",
                details=_error_message(exc),
            ) from exc
        raise

    try:
        s3_client.head_object(Bucket=bucket_name, Key=request.object_key)
    except ClientError as exc:
        if _is_not_found_error(exc):
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
    del context
    try:
        request = parse_input(event)
        return _response(200, generate_download_url(request))
    except BadRequestError as exc:
        return _error_response(400, "Bad request", str(exc))
    except MethodNotAllowedError as exc:
        return _error_response(405, "method_not_allowed", str(exc))
    except NotFoundError as exc:
        return _error_response(404, exc.error, exc.message, details=exc.details)
    except Exception as exc:
        return _error_response(500, "Internal error", str(exc))
