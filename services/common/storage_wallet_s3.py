"""
Shared helpers for wallet-scoped storage Lambdas: API Gateway JSON bodies, EIP-55-ish
address checks, authorizer context, mnemospark S3 bucket naming, and list_objects_v2.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError


class BadRequestError(ValueError):
    """Invalid request input for storage Lambdas."""


class ForbiddenError(ValueError):
    """Authorizer wallet context missing, invalid, or mismatched."""


class S3ListBucketAccessError(Exception):
    """list_objects_v2 failed because the bucket is missing or inaccessible."""


class S3ListContinuationError(Exception):
    """list_objects_v2 rejected the continuation token."""


ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")

NOT_FOUND_S3_ERROR_CODES = frozenset(
    {
        "403",
        "404",
        "AccessDenied",
        "AllAccessDisabled",
        "NoSuchBucket",
        "NoSuchKey",
        "NotFound",
    }
)

INVALID_LIST_ARGUMENT_S3_ERROR_CODES = frozenset({"InvalidArgument"})

NOT_FOUND_S3_ERROR_CODES_DOWNLOAD = frozenset({"404", "NotFound", "NoSuchBucket", "NoSuchKey"})

BUCKET_NAME_MIN_LEN = 3
BUCKET_NAME_MAX_LEN = 63
BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
BUCKET_FORBIDDEN_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
BUCKET_FORBIDDEN_SUFFIXES = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
BUCKET_IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def decode_json_event_body(event: dict[str, Any]) -> dict[str, Any]:
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


def normalize_wallet_address(value: str, field_name: str) -> str:
    candidate = value.strip()
    if not ADDRESS_PATTERN.fullmatch(candidate):
        raise BadRequestError(f"{field_name} must be a 0x-prefixed 20-byte hex address")
    return f"0x{candidate[2:].lower()}"


def extract_authorizer_wallet_address(event: dict[str, Any]) -> str | None:
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
            return normalize_wallet_address(candidate, "authorizer walletAddress")
        except BadRequestError as exc:
            raise ForbiddenError("wallet authorization context is invalid") from exc
    return None


def require_authorized_wallet_match(event: dict[str, Any], wallet_address: str) -> None:
    authorized_wallet = extract_authorizer_wallet_address(event)
    if authorized_wallet is None:
        raise ForbiddenError("wallet authorization context is required")
    if authorized_wallet != wallet_address:
        raise ForbiddenError("wallet_address does not match authorized wallet")


def get_required_authorizer_wallet(event: dict[str, Any]) -> str:
    """Return normalized wallet from authorizer context or raise ForbiddenError."""
    wallet = extract_authorizer_wallet_address(event)
    if wallet is None:
        raise ForbiddenError("wallet authorization context is required")
    return wallet


def wallet_hash_hex(wallet_address: str, length: int = 16) -> str:
    return hashlib.sha256(wallet_address.encode("utf-8")).hexdigest()[:length]


def bucket_name_from_wallet(wallet_address: str) -> str:
    return f"mnemospark-{wallet_hash_hex(wallet_address)}"


def validate_bucket_naming_rules(name: str) -> None:
    if not (BUCKET_NAME_MIN_LEN <= len(name) <= BUCKET_NAME_MAX_LEN):
        raise ValueError(f"Bucket name must be {BUCKET_NAME_MIN_LEN}-{BUCKET_NAME_MAX_LEN} characters")
    if not BUCKET_NAME_PATTERN.match(name):
        raise ValueError("Bucket name must use only lowercase letters, digits, dots, and hyphens")
    if name.startswith(BUCKET_FORBIDDEN_PREFIXES) or name.endswith(BUCKET_FORBIDDEN_SUFFIXES):
        raise ValueError("Bucket name uses a forbidden prefix or suffix")
    if BUCKET_IP_PATTERN.match(name):
        raise ValueError("Bucket name must not be formatted as an IP address")


def s3_error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def s3_not_found_for_download(exc: ClientError) -> bool:
    return s3_error_code(exc) in NOT_FOUND_S3_ERROR_CODES_DOWNLOAD


def s3_last_modified_iso_utc(dt: Any) -> str | None:
    if dt is None or not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def parse_optional_string_param(params: dict[str, Any], field: str) -> str | None:
    raw = params.get(field)
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise BadRequestError(f"{field} must be a string")
    s = raw.strip()
    return s or None


def parse_list_max_keys_field(
    raw: Any,
    *,
    default: int,
    cap: int,
) -> int:
    if raw in (None, ""):
        return default
    if isinstance(raw, bool):
        raise BadRequestError(f"max_keys must be an integer between 1 and {cap}")
    if isinstance(raw, str):
        try:
            raw = int(raw.strip(), 10)
        except ValueError as exc:
            raise BadRequestError(f"max_keys must be an integer between 1 and {cap}") from exc
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise BadRequestError(f"max_keys must be an integer between 1 and {cap}")
    if raw < 1 or raw > cap:
        raise BadRequestError(f"max_keys must be an integer between 1 and {cap}")
    return raw


def parse_list_max_keys_from_params(
    params: dict[str, Any],
    *,
    default: int,
    cap: int,
) -> int:
    return parse_list_max_keys_field(params.get("max_keys"), default=default, cap=cap)


def validate_object_key_single_segment(object_key: str) -> str:
    object_key = object_key.strip()
    if not object_key or "/" in object_key or "\\" in object_key or object_key in {".", ".."}:
        raise BadRequestError("object_key must be a single path segment")
    return object_key


def coerce_presigned_ttl_seconds(
    value: Any,
    *,
    default: int,
    minimum: int = 1,
    maximum: int = 3600,
) -> int:
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise BadRequestError("expires_in_seconds must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise BadRequestError(f"expires_in_seconds must be between {minimum} and {maximum}")
    return parsed


def list_objects_v2_page(
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
        code = s3_error_code(exc)
        if code in NOT_FOUND_S3_ERROR_CODES:
            raise S3ListBucketAccessError("Bucket not found for this wallet") from exc
        if code in INVALID_LIST_ARGUMENT_S3_ERROR_CODES:
            raise S3ListContinuationError("continuation_token is invalid or expired") from exc
        raise
