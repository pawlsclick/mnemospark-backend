"""
Lambda handler for GET/POST /storage/ls.

Returns metadata for one object in the wallet-scoped bucket:
{
  "success": true,
  "key": "<object-key>",
  "size_bytes": <size>,
  "bucket": "mnemospark-<wallet-hash>"
}
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


class BadRequestError(ValueError):
    """Raised when request validation fails."""


@dataclass(frozen=True)
class NotFoundError(Exception):
    error: str
    message: str


@dataclass(frozen=True)
class ParsedLsRequest:
    wallet_address: str
    object_key: str
    location: str


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


def _assert_bucket_access(s3_client: Any, bucket_name: str) -> None:
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if _error_code(exc) in NOT_FOUND_S3_ERROR_CODES:
            raise NotFoundError("bucket_not_found", "Bucket not found for this wallet") from exc
        raise


def _get_object_size(s3_client: Any, bucket_name: str, object_key: str) -> int:
    try:
        response = s3_client.head_object(Bucket=bucket_name, Key=object_key)
    except ClientError as exc:
        if _error_code(exc) in NOT_FOUND_S3_ERROR_CODES:
            raise NotFoundError("object_not_found", f"Object not found: {object_key}") from exc
        raise
    return int(response.get("ContentLength", 0))


def parse_input(event: dict[str, Any]) -> ParsedLsRequest:
    params = _collect_request_params(event)

    wallet_address = _normalize_address(_require_string_field(params, "wallet_address"), "wallet_address")
    object_key = _require_string_field(params, "object_key")
    _validate_object_key(object_key)
    location = str(params.get("location") or params.get("region") or DEFAULT_LOCATION).strip() or DEFAULT_LOCATION

    return ParsedLsRequest(wallet_address=wallet_address, object_key=object_key, location=location)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    try:
        request = parse_input(event)
        s3_client = boto3.client("s3", region_name=request.location)
        bucket_name = _bucket_name(request.wallet_address)

        try:
            _validate_bucket_name(bucket_name)
        except ValueError as exc:
            raise BadRequestError(str(exc)) from exc

        _assert_bucket_access(s3_client, bucket_name)
        object_size = _get_object_size(s3_client, bucket_name, request.object_key)

        return _response(
            200,
            {
                "success": True,
                "key": request.object_key,
                "size_bytes": object_size,
                "bucket": bucket_name,
            },
        )
    except BadRequestError as exc:
        return _error_response(400, "Bad request", str(exc))
    except NotFoundError as exc:
        return _error_response(404, exc.error, exc.message)
    except Exception as exc:
        return _error_response(500, "Internal error", str(exc))
