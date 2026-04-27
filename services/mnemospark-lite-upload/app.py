"""
mnemospark-lite marketplace storage facade.

Routes:
  POST /api/mnemospark-lite/upload          (paid; x402)
  POST /api/mnemospark-lite/upload/complete (free; completion_token)
  GET  /api/mnemospark-lite/uploads         (bearer/JWT)
  GET  /api/mnemospark-lite/download/{id}   (bearer/JWT)

v1 constraints:
  - No multipart uploads
  - Hard max size: 4.8 GB (4_800_000_000 bytes)
  - `publicUrl` is an app-entry URL (ls-web exchange code), not an anonymous bytes URL
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import hashlib
import hmac
import base64
import time
from decimal import Decimal
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote

import boto3
from botocore.exceptions import ClientError
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
import socket

try:
    from common.eip3009_verification import TRANSFER_WITH_AUTH_TYPES, normalize_transfer_with_auth_nonce
    from common.http_response_headers import rest_api_json_headers
    from common.storage_wallet_s3 import (
        BadRequestError,
        ForbiddenError,
        decode_json_event_body,
        normalize_wallet_address,
        s3_error_code,
        validate_object_key_single_segment,
    )
except ModuleNotFoundError:  # pragma: no cover
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.eip3009_verification import TRANSFER_WITH_AUTH_TYPES, normalize_transfer_with_auth_nonce
    from common.http_response_headers import rest_api_json_headers
    from common.storage_wallet_s3 import (
        BadRequestError,
        ForbiddenError,
        decode_json_event_body,
        normalize_wallet_address,
        s3_error_code,
        validate_object_key_single_segment,
    )

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

US_EAST_1_REGION = "us-" + "east-1"
DEFAULT_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or US_EAST_1_REGION

MAX_UPLOAD_SIZE_BYTES = 4_800_000_000
DEFAULT_PRESIGN_TTL_SECONDS = 900
X402_PRICE_MICRO_USDC = 20_000  # $0.02 in USDC (6 decimals)

s3 = boto3.client("s3", region_name=DEFAULT_REGION)
dynamodb = boto3.resource("dynamodb", region_name=DEFAULT_REGION)

LIFECYCLE_EXPIRE_DAYS = 30
_LIFECYCLE_ENSURED_BUCKETS: set[str] = set()


class UnauthorizedError(ValueError):
    pass


class SettlementPendingError(RuntimeError):
    pass


class PaymentInvalidError(ValueError):
    pass


def _chain_id_from_caip2(network: str) -> int:
    raw = (network or "").strip().lower()
    if raw.startswith("eip155:"):
        try:
            return int(raw.split(":", 1)[1])
        except Exception as exc:
            raise BadRequestError(f"Invalid CAIP-2 network: {network!r}") from exc
    raise BadRequestError(f"Unsupported network (expected CAIP-2 eip155:*): {network!r}")


def _normalize_nonce(nonce: Any) -> str:
    return normalize_transfer_with_auth_nonce(nonce, error_cls=BadRequestError)


def _require_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadRequestError(f"{field} must be an integer")
    return value


def _coerce_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise BadRequestError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isascii() and stripped.isdecimal():
            try:
                return int(stripped)
            except ValueError:
                pass
    raise BadRequestError(f"{field} must be an integer")


def _verify_payment_locally(*, payment_payload: dict[str, Any], requirement: dict[str, Any]) -> None:
    """
    Local EIP-712 verification for EIP-3009 TransferWithAuthorization.
    Avoids external facilitator calls on the /upload critical path.
    """
    payload_obj = payment_payload.get("payload")
    if not isinstance(payload_obj, dict):
        raise BadRequestError("payment payload must include payload object")
    authorization = payload_obj.get("authorization")
    signature = payload_obj.get("signature")
    if not isinstance(authorization, dict) or not isinstance(signature, str) or not signature.strip():
        raise BadRequestError("payment payload missing authorization/signature")
    if not signature.startswith("0x") or len(signature.strip()) != 132:
        raise BadRequestError("payment signature must be a 65-byte hex string")

    from_addr = normalize_wallet_address(str(authorization.get("from") or ""), "payment from")
    to_addr = normalize_wallet_address(str(authorization.get("to") or ""), "payment to")
    value = _coerce_int(authorization.get("value"), "payment value")
    valid_after = _coerce_int(authorization.get("validAfter"), "payment validAfter")
    valid_before = _coerce_int(authorization.get("validBefore"), "payment validBefore")
    nonce = _normalize_nonce(authorization.get("nonce"))

    expected_to = normalize_wallet_address(str(requirement.get("payTo") or ""), "payment payTo")
    expected_asset = normalize_wallet_address(str(requirement.get("asset") or ""), "payment asset")
    expected_value = _coerce_int(requirement.get("amount"), "payment amount")
    expected_network = str(requirement.get("network") or "").strip()
    if not expected_network:
        raise BadRequestError("payment network is required")

    if to_addr != expected_to:
        raise PaymentInvalidError("payment recipient does not match payTo")
    if value != expected_value:
        raise PaymentInvalidError("payment amount does not match requirement")

    now = int(time.time())
    if valid_after > now:
        raise PaymentInvalidError("payment authorization is not yet valid")
    if valid_before <= now:
        raise PaymentInvalidError("payment authorization has expired")

    extra = requirement.get("extra") if isinstance(requirement.get("extra"), dict) else {}
    domain_name = str(extra.get("name") or "")
    domain_version = str(extra.get("version") or "")
    if not domain_name or not domain_version:
        raise BadRequestError("EIP-712 domain name/version required in requirement.extra")

    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("eth-account is required for local payment verification") from exc

    chain_id = _chain_id_from_caip2(expected_network)
    try:
        signable = encode_typed_data(
            domain_data={
                "name": domain_name,
                "version": domain_version,
                "chainId": chain_id,
                "verifyingContract": expected_asset,
            },
            message_types=TRANSFER_WITH_AUTH_TYPES,
            message_data={
                "from": from_addr,
                "to": to_addr,
                "value": int(value),
                "validAfter": int(valid_after),
                "validBefore": int(valid_before),
                "nonce": nonce,
            },
        )
        recovered = Account.recover_message(signable, signature=signature.strip())
    except Exception as exc:
        raise PaymentInvalidError("payment signature is invalid") from exc
    recovered_norm = normalize_wallet_address(recovered, "recovered signer")
    if recovered_norm != from_addr:
        raise PaymentInvalidError("payment signature does not recover payer wallet")

def _uploads_table() -> Any:
    name = (os.environ.get("MNEMOSPARK_LITE_UPLOADS_TABLE_NAME") or "").strip()
    if not name:
        raise RuntimeError("MNEMOSPARK_LITE_UPLOADS_TABLE_NAME is not configured")
    return dynamodb.Table(name)


def _ls_web_session_table() -> Any:
    name = (os.environ.get("LS_WEB_SESSION_TABLE_NAME") or "").strip()
    if not name:
        raise RuntimeError("LS_WEB_SESSION_TABLE_NAME is not configured")
    return dynamodb.Table(name)


def _bearer_secret() -> bytes:
    raw = (os.environ.get("MNEMOSPARK_LITE_BEARER_SECRET") or "").strip()
    if not raw:
        raise RuntimeError("MNEMOSPARK_LITE_BEARER_SECRET is not configured")
    return raw.encode("utf-8")


def _response(status_code: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    merged = rest_api_json_headers()
    if headers:
        merged.update(headers)
    return {"statusCode": status_code, "headers": merged, "body": json.dumps(body, default=str)}


def _error(status_code: int, error: str, message: str, details: Any | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": error, "message": message}
    if details is not None:
        payload["details"] = details
    return _response(status_code, payload)


def _path(event: dict[str, Any]) -> str:
    raw = event.get("path") or ""
    if not isinstance(raw, str):
        return ""
    return raw


def _method(event: dict[str, Any]) -> str:
    raw = event.get("httpMethod") or ""
    return str(raw).upper()


def _bearer_token(event: dict[str, Any]) -> str | None:
    headers = event.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    auth = headers.get("Authorization") or headers.get("authorization")
    if not isinstance(auth, str):
        return None
    auth = auth.strip()
    if not auth.lower().startswith("bearer "):
        return None
    token = auth[7:].strip()
    return token or None


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _sign_bearer(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body_b64 = _b64url_encode(body)
    sig = hmac.new(_bearer_secret(), body_b64.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{body_b64}.{sig_b64}"


def _verify_bearer(token: str) -> dict[str, Any]:
    if "." not in token:
        raise UnauthorizedError("Invalid bearer token")
    body_b64, sig_b64 = token.split(".", 1)
    expected = hmac.new(_bearer_secret(), body_b64.encode("utf-8"), hashlib.sha256).digest()
    try:
        actual = _b64url_decode(sig_b64)
    except Exception as exc:
        raise UnauthorizedError("Invalid bearer token") from exc
    if not hmac.compare_digest(expected, actual):
        raise UnauthorizedError("Invalid bearer token")
    try:
        payload = json.loads(_b64url_decode(body_b64).decode("utf-8"))
    except Exception as exc:
        raise UnauthorizedError("Invalid bearer token") from exc
    if not isinstance(payload, dict):
        raise UnauthorizedError("Invalid bearer token")
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp <= 0:
        raise UnauthorizedError("Invalid bearer token")
    if int(time.time()) > exp:
        raise UnauthorizedError("Bearer token expired")
    wallet = payload.get("w")
    if not isinstance(wallet, str) or not wallet.strip():
        raise UnauthorizedError("Invalid bearer token")
    payer_wallet = normalize_wallet_address(wallet, "bearer wallet")
    return {"payer_wallet": payer_wallet}


@dataclass(frozen=True)
class UploadRequest:
    filename: str
    content_type: str
    tier: str
    size_bytes: int


def _parse_upload_request(body: dict[str, Any]) -> UploadRequest:
    filename_raw = body.get("filename")
    content_type_raw = body.get("contentType") or body.get("content_type")
    tier_raw = body.get("tier")
    size_bytes_raw = body.get("size_bytes")
    if size_bytes_raw is None:
        size_bytes_raw = body.get("sizeBytes")
    if size_bytes_raw is None:
        size_bytes_raw = body.get("size")

    if not isinstance(filename_raw, str) or not filename_raw.strip():
        raise BadRequestError("filename is required")
    filename = validate_object_key_single_segment(filename_raw)

    if not isinstance(content_type_raw, str) or not content_type_raw.strip():
        raise BadRequestError("contentType is required")
    content_type = content_type_raw.strip()

    if not isinstance(tier_raw, str) or not tier_raw.strip():
        raise BadRequestError("tier is required")
    tier = tier_raw.strip()

    size_bytes = _require_int(size_bytes_raw, "size_bytes")
    if size_bytes < 0:
        raise BadRequestError("size_bytes must be non-negative")
    if size_bytes > MAX_UPLOAD_SIZE_BYTES:
        raise BadRequestError(f"size_bytes exceeds max upload size ({MAX_UPLOAD_SIZE_BYTES} bytes)")

    return UploadRequest(filename=filename, content_type=content_type, tier=tier, size_bytes=size_bytes)


def _bucket_name_from_wallet_lite(wallet_address: str) -> str:
    # Intentionally service-local: lite-upload bucket routing is a separate concern
    # from other services and may diverge without changing shared helpers.
    # Keep hashing behavior aligned with common.storage_wallet_s3.wallet_hash_hex.
    import hashlib

    h = hashlib.sha256(wallet_address.encode("utf-8")).hexdigest()[:16]
    return f"mnemospark-lite-{h}"


def _expires_at_iso(now: datetime) -> str:
    expires_at = now + timedelta(days=30)
    expires_at = expires_at.astimezone(timezone.utc)
    return expires_at.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _created_at_iso(now: datetime) -> str:
    now = now.astimezone(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _ttl_epoch_seconds(now: datetime) -> int:
    # registry TTL: keep a buffer after eligibility; 31 days should be enough for lifecycle lag
    return int((now + timedelta(days=31)).timestamp())


def _tier_max_size_bytes(tier: str) -> int:
    t = tier.strip().lower()
    mapping: dict[str, int] = {
        "10mb": 10 * 1_000_000,
        "100mb": 100 * 1_000_000,
        "500mb": 500 * 1_000_000,
        "1gb": 1 * 1_000_000_000,
        "2gb": 2 * 1_000_000_000,
        "3gb": 3 * 1_000_000_000,
    }
    if t not in mapping:
        raise BadRequestError("tier is invalid")
    return mapping[t]


def _ensure_bucket_lifecycle_expiration(*, bucket: str) -> None:
    # Bucket-level lifecycle: expire objects after 30 days. This enforces retention without a sweeper.
    if bucket in _LIFECYCLE_ENSURED_BUCKETS:
        return

    rule_id = f"mnemospark-lite-expire-{LIFECYCLE_EXPIRE_DAYS}d"
    desired_rule = {
        "ID": rule_id,
        "Status": "Enabled",
        "Filter": {"Prefix": ""},
        "Expiration": {"Days": LIFECYCLE_EXPIRE_DAYS},
        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
    }
    existing_rules: list[dict[str, Any]]
    try:
        resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
        raw_rules = resp.get("Rules") or []
        existing_rules = [rule for rule in raw_rules if isinstance(rule, dict)]
    except ClientError as exc:
        code = s3_error_code(exc)
        if code in {"NoSuchLifecycleConfiguration", "404", "NotFound"}:
            existing_rules = []
        else:
            raise

    if any(str(rule.get("ID") or "") == rule_id for rule in existing_rules):
        _LIFECYCLE_ENSURED_BUCKETS.add(bucket)
        return

    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={"Rules": [*existing_rules, desired_rule]},
    )
    _LIFECYCLE_ENSURED_BUCKETS.add(bucket)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _mint_ls_web_app_url(*, payer_wallet: str, location: str) -> dict[str, str]:
    now = int(time.time())
    session_ttl = 21600
    expires_at = now + session_ttl
    session_id = secrets.token_urlsafe(32)
    code = secrets.token_urlsafe(32)
    code_hash = _hash_token(code)
    _ls_web_session_table().put_item(
        Item={
            "session_id": session_id,
            "wallet_address": payer_wallet,
            "location": location,
            # Tell ls-web BFF to list/download from mnemospark-lite-* buckets for this session.
            "bucket_mode": "lite",
            "exchange_code_hash": code_hash,
            "exchanged": False,
            "session_expires_at": expires_at,
            "expires_at": expires_at,
        },
        ConditionExpression="attribute_not_exists(session_id)",
    )
    app_base = (os.environ.get("MNEMOSPARK_LS_WEB_APP_URL") or "https://app.mnemospark.ai").strip().rstrip("/")
    prefix_query = (os.environ.get("MNEMOSPARK_LS_WEB_APP_PREFIX_QUERY") or "").strip()
    from urllib.parse import quote

    enc_q = quote(code, safe="")
    if prefix_query:
        app = f"{app_base}/?{prefix_query}&code={enc_q}"
    else:
        app = f"{app_base}/?code={enc_q}"
    return {
        "code": code,
        "app": app,
        "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z",
    }


def _payment_config() -> dict[str, str]:
    recipient_wallet_raw = os.environ.get("MNEMOSPARK_RECIPIENT_WALLET", "").strip()
    payment_network_raw = os.environ.get("MNEMOSPARK_PAYMENT_NETWORK", "").strip()
    payment_asset_raw = os.environ.get("MNEMOSPARK_PAYMENT_ASSET", "").strip()
    if not recipient_wallet_raw:
        raise RuntimeError("MNEMOSPARK_RECIPIENT_WALLET is not configured")
    if not payment_network_raw:
        raise RuntimeError("MNEMOSPARK_PAYMENT_NETWORK is not configured")
    if not payment_asset_raw:
        raise RuntimeError("MNEMOSPARK_PAYMENT_ASSET is not configured")
    # network is CAIP-2 in template, asset/payTo are 0x addresses.
    recipient_wallet = normalize_wallet_address(recipient_wallet_raw, "recipient_wallet")
    payment_asset = normalize_wallet_address(payment_asset_raw, "payment_asset")
    return {"recipient_wallet": recipient_wallet, "payment_network": payment_network_raw, "payment_asset": payment_asset}


def _public_base_url() -> str:
    raw = (os.environ.get("MNEMOSPARK_LITE_PUBLIC_BASE_URL") or "").strip().rstrip("/")
    if not raw:
        raise RuntimeError("MNEMOSPARK_LITE_PUBLIC_BASE_URL is not configured")
    return raw


def _bazaar_extension_for_upload() -> dict[str, Any]:
    return {
        "bazaar": {
            "info": {
                "description": (
                    "Paid file upload endpoint for mnemospark-lite. "
                    "Creates a presigned S3 upload session, then finalizes the upload "
                    "into a wallet-scoped 30-day object store."
                ),
                "input": {
                    "type": "http",
                    "method": "POST",
                    "bodyType": "json",
                    "body": {
                        "filename": "example.pdf",
                        "contentType": "application/pdf",
                        "tier": "100mb",
                        "size_bytes": 24576,
                    },
                },
                "output": {
                    "type": "json",
                    "example": {
                        "success": True,
                        "data": {
                            "uploadId": "abc123",
                            "uploadUrl": "https://s3-presigned.example/...",
                            "publicUrl": None,
                            "siteUrl": None,
                            "expiresAt": "2026-05-23T12:00:00Z",
                            "maxSize": 100000000,
                            "curlExample": "curl -X PUT --data-binary @\"example.pdf\" ...",
                            "completion_token": "opaque-token",
                            "list_scope_bearer": "opaque-bearer",
                        },
                        "metadata": {
                            "protocol": "x402",
                            "network": "eip155:8453",
                            "price": "$0.02",
                            "payment": {
                                "success": True,
                                "transactionHash": None,
                                "status": "verified",
                            },
                        },
                    },
                    "schema": {
                        "type": "object",
                        "properties": {
                            "success": {"type": "boolean"},
                            "data": {
                                "type": "object",
                                "properties": {
                                    "uploadId": {"type": "string"},
                                    "uploadUrl": {"type": "string"},
                                    "publicUrl": {"type": ["string", "null"]},
                                    "siteUrl": {"type": ["string", "null"]},
                                    "expiresAt": {"type": "string"},
                                    "maxSize": {"type": "integer"},
                                    "curlExample": {"type": "string"},
                                    "completion_token": {"type": "string"},
                                    "list_scope_bearer": {"type": "string"},
                                },
                                "required": [
                                    "uploadId",
                                    "uploadUrl",
                                    "expiresAt",
                                    "maxSize",
                                    "completion_token",
                                    "list_scope_bearer",
                                ],
                            },
                            "metadata": {"type": "object"},
                        },
                        "required": ["success", "data"],
                    },
                },
            },
            "schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "input": {
                        "type": "object",
                        "properties": {
                            "type": {"const": "http"},
                            "method": {"const": "POST"},
                            "bodyType": {"const": "json"},
                            "body": {
                                "type": "object",
                                "properties": {
                                    "filename": {"type": "string", "description": "Single file name"},
                                    "contentType": {"type": "string", "description": "MIME type"},
                                    "tier": {
                                        "type": "string",
                                        "enum": ["10mb", "100mb", "500mb", "1gb", "2gb", "3gb"],
                                        "description": "Upload pricing/size tier",
                                    },
                                    "size_bytes": {
                                        "type": "integer",
                                        "minimum": 0,
                                        "maximum": MAX_UPLOAD_SIZE_BYTES,
                                        "description": "Declared upload size in bytes",
                                    },
                                },
                                "required": ["filename", "contentType", "tier", "size_bytes"],
                                "additionalProperties": False,
                            },
                        },
                        "required": ["type", "method", "bodyType", "body"],
                        "additionalProperties": False,
                    },
                    "output": {
                        "type": "object",
                        "properties": {
                            "type": {"const": "json"},
                            "example": {"type": "object"},
                            "schema": {"type": "object"},
                        },
                        "required": ["type", "example"],
                        "additionalProperties": True,
                    },
                },
                "required": ["description", "input", "output"],
                "additionalProperties": False,
            },
        }
    }


def _payment_requirements() -> dict[str, Any]:
    cfg = _payment_config()
    resource = f"{_public_base_url()}/api/mnemospark-lite/upload"
    return {
        "x402Version": 2,
        "resource": resource,
        "description": (
            "mnemospark-lite paid file upload API for wallet-scoped storage. "
            "Returns a presigned S3 upload URL, completion token, and bearer for listing "
            "and downloading uploaded files. Files expire automatically after 30 days."
        ),
        "mimeType": "application/json",
        "accepts": [
            {
                "scheme": "exact",
                "network": cfg["payment_network"],
                "asset": cfg["payment_asset"],
                "payTo": cfg["recipient_wallet"],
                "amount": str(X402_PRICE_MICRO_USDC),
                # CDP x402 V2 PaymentRequirements expects these fields.
                "maxTimeoutSeconds": 3600,
                # For EIP-3009 (USDC), facilitator needs EIP-712 domain info.
                "extra": {"name": "USD Coin", "version": "2"},
            }
        ],
        "extensions": _bazaar_extension_for_upload(),
    }


def _strip_nulls(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if v is None:
                continue
            out[str(k)] = _strip_nulls(v)
        return out
    if isinstance(value, list):
        return [_strip_nulls(v) for v in value]
    return value


def _json_sanitize(value: Any) -> Any:
    """
    DynamoDB returns numbers as Decimal; CDP expects JSON-serializable primitives.
    Convert Decimals to int/float (prefer int when integral) recursively.
    """
    if isinstance(value, Decimal):
        try:
            if value == value.to_integral_value():
                return int(value)
        except Exception:
            pass
        return float(value)
    if isinstance(value, dict):
        return {str(k): _json_sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_sanitize(v) for v in value]
    return value


def _format_usdc_price(amount_micro: int) -> str:
    # USDC has 6 decimals.
    return f"${amount_micro / 1_000_000:.2f}"


def _encode_json_base64(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(encoded).decode("ascii")


def _x402_payment_required_headers(requirements: dict[str, Any]) -> dict[str, str]:
    encoded = _encode_json_base64(requirements)
    return {"PAYMENT-REQUIRED": encoded, "x-payment-required": encoded}


def _normalize_headers(event: dict[str, Any]) -> dict[str, str]:
    raw = event.get("headers") or {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or v is None:
            continue
        out[k.strip().lower()] = str(v).strip()
    return out


def _decode_payment_payload(payment_header: str) -> dict[str, Any]:
    candidates: list[str] = [payment_header]
    try:
        decoded = base64.b64decode(payment_header, validate=True).decode("utf-8")
        candidates.insert(0, decoded)
    except Exception:
        pass
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise BadRequestError("payment header must be base64-encoded JSON")


def _cdp_facilitator_bearer_token(*, request_method: str, request_host: str, request_path: str) -> str:
    # CDP uses short-lived JWT auth derived from (api key id, api key secret)
    # scoped to request method + host + path. Docs:
    # https://docs.cdp.coinbase.com/get-started/authentication/jwt-authentication
    key_id = (os.environ.get("CDP_API_KEY_ID") or "").strip()
    key_secret = (os.environ.get("CDP_API_KEY_SECRET") or "").strip()
    if not key_id or not key_secret:
        raise RuntimeError("CDP facilitator auth is not configured (set CDP_API_KEY_ID + CDP_API_KEY_SECRET)")

    try:
        # Newer SDK import path
        from cdp.auth import JwtOptions, generate_jwt  # type: ignore
    except ImportError:
        try:
            # Older SDK import path
            from cdp.auth.utils.jwt import JwtOptions, generate_jwt  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("cdp-sdk is required for CDP JWT auth (install cdp-sdk)") from exc

    token = generate_jwt(
        JwtOptions(
            api_key_id=key_id,
            api_key_secret=key_secret,
            request_method=request_method,
            request_host=request_host,
            request_path=request_path,
            expires_in=120,
        )
    )
    return f"Bearer {token}"


def _cdp_post(path: str, payload: dict[str, Any], *, timeout_seconds: float = 10.0) -> dict[str, Any]:
    request_host = "api.cdp.coinbase.com"
    request_path = f"/platform{path}"
    url = f"https://{request_host}{request_path}"
    data = json.dumps(_json_sanitize(payload), separators=(",", ":")).encode("utf-8")
    # urllib checks for "Content-type" specifically before auto-inserting its
    # default form-encoded content type, so use that key casing explicitly.
    headers = {
        "Content-type": "application/json",
        "Authorization": _cdp_facilitator_bearer_token(
            request_method="POST",
            request_host=request_host,
            request_path=request_path,
        ),
    }
    req = urllib_request.Request(url, data=data, method="POST")
    # Avoid Request.add_header(), which lowercases custom header names.
    req.headers.update(headers)
    try:
        with urllib_request.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw else {}
            if not isinstance(parsed, dict):
                raise RuntimeError("CDP response must be a JSON object")
            return parsed
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if 400 <= exc.code < 500:
            raise BadRequestError(f"CDP facilitator error ({exc.code}): {body}") from exc
        raise RuntimeError(f"CDP facilitator error ({exc.code}): {body}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise SettlementPendingError("CDP request timed out") from exc
    except URLError as exc:
        raise RuntimeError("Unable to reach CDP facilitator") from exc


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    path = _path(event)
    method = _method(event)

    try:
        if method == "POST" and path == "/api/mnemospark-lite/upload":
            return _handle_post_upload(event)
        if method == "POST" and path == "/api/mnemospark-lite/upload/complete":
            return _handle_post_complete(event)
        if method == "GET" and path == "/api/mnemospark-lite/uploads":
            return _handle_get_uploads(event)
        if method == "GET" and path.startswith("/api/mnemospark-lite/download/"):
            upload_id = unquote(path.split("/api/mnemospark-lite/download/", 1)[1] or "").strip()
            if not upload_id:
                raise BadRequestError("uploadId is required")
            return _handle_get_download(event, upload_id=upload_id)

        return _error(404, "not_found", "Route not found")
    except PaymentInvalidError as exc:
        return _error(402, "payment_invalid", str(exc))
    except BadRequestError as exc:
        return _error(400, "bad_request", str(exc))
    except UnauthorizedError as exc:
        return _error(403, "forbidden", str(exc))
    except ForbiddenError as exc:
        return _error(403, "forbidden", str(exc))
    except ClientError as exc:
        code = s3_error_code(exc)
        logger.info("AWS ClientError code=%s", code)
        return _error(500, "aws_error", "AWS error", {"code": code})
    except Exception:
        logger.exception("Unhandled error")
        return _error(500, "internal_error", "Internal error")


def _handle_post_upload(event: dict[str, Any]) -> dict[str, Any]:
    headers = _normalize_headers(event)
    payment_header = headers.get("payment-signature") or headers.get("x-payment")
    requirements = _payment_requirements()
    accepts = requirements.get("accepts") if isinstance(requirements, dict) else None
    requirement = accepts[0] if isinstance(accepts, list) and accepts else None
    if not isinstance(requirement, dict):
        raise RuntimeError("Payment requirements are misconfigured (expected accepts[0])")

    # Important for Bazaar crawl / empty-body probes: discovery requests may send no body.
    if not payment_header:
        return _response(
            402,
            {"error": "payment_required", "message": "Payment is required."},
            headers=_x402_payment_required_headers(requirements),
        )

    body = decode_json_event_body(event)
    req = _parse_upload_request(body)
    max_size = _tier_max_size_bytes(req.tier)
    if req.size_bytes > max_size:
        raise BadRequestError(f"size_bytes exceeds tier max size ({max_size} bytes)")
    payment_payload = _decode_payment_payload(payment_header)

    # Extract/validate the payer wallet from the payment payload BEFORE settling.
    # This prevents "paid but got 400" scenarios if the facilitator settles but
    # returns a missing/malformed payer field.
    payload_obj = payment_payload.get("payload") if isinstance(payment_payload, dict) else None
    payload_obj = payload_obj if isinstance(payload_obj, dict) else {}
    payer_raw = ""
    auth = payload_obj.get("authorization")
    if isinstance(auth, dict):
        payer_raw = str(auth.get("from") or "")
    if not payer_raw:
        permit2_auth = payload_obj.get("permit2Authorization")
        if isinstance(permit2_auth, dict):
            payer_raw = str(permit2_auth.get("from") or "")
    payer_wallet = normalize_wallet_address(payer_raw, "payer_wallet")

    # Verify locally (fast, no external dependency). Settlement happens later in
    # /complete to avoid API Gateway timeouts.
    _verify_payment_locally(payment_payload=payment_payload, requirement=requirement)

    now = datetime.now(timezone.utc)
    upload_id = secrets.token_urlsafe(16)
    completion_token = secrets.token_urlsafe(32)
    completion_token_hash = _hash_token(completion_token)
    bucket = _bucket_name_from_wallet_lite(payer_wallet)
    object_key = f"{upload_id}/{req.filename}"

    # Create bucket if missing (same behavior as existing workflow).
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        code = s3_error_code(exc)
        if code in {"404", "NoSuchBucket", "NotFound"}:
            normalized_region = (DEFAULT_REGION or "").strip()
            if not normalized_region or normalized_region == US_EAST_1_REGION:
                s3.create_bucket(Bucket=bucket)
            else:
                s3.create_bucket(
                    Bucket=bucket,
                    CreateBucketConfiguration={"LocationConstraint": normalized_region},
                )
        else:
            raise
    try:
        _ensure_bucket_lifecycle_expiration(bucket=bucket)
    except ClientError as exc:
        logger.warning(
            "Failed to ensure lifecycle policy for bucket %s (code=%s); continuing upload creation",
            bucket,
            s3_error_code(exc),
        )

    upload_url = s3.generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket, "Key": object_key, "ContentType": req.content_type},
        ExpiresIn=DEFAULT_PRESIGN_TTL_SECONDS,
    )
    curl_example = f"curl -X PUT --data-binary @\"{req.filename}\" -H \"Content-Type: {req.content_type}\" \"{upload_url}\""

    bearer = _sign_bearer({"w": payer_wallet, "exp": int(time.time()) + 86400})
    price_micro = int(requirement.get("amount") or X402_PRICE_MICRO_USDC)

    item = {
        "upload_id": upload_id,
        "payer_wallet": payer_wallet,
        "bucket": bucket,
        "filename": req.filename,
        "object_key": object_key,
        "content_type": req.content_type,
        "tier": req.tier,
        "max_size": max_size,
        "status": "pending",
        "actual_size": None,
        "public_url": None,
        "site_url": None,
        "created_at": _created_at_iso(now),
        "expires_at": _expires_at_iso(now),
        "ttl_epoch_seconds": _ttl_epoch_seconds(now),
        "completion_token_hash": completion_token_hash,
        "transaction_hash": None,
        "payment_status": "verified",
        "payment_payload": _strip_nulls(payment_payload),
        "payment_requirements": requirement,
        "price_paid": _format_usdc_price(price_micro),
        "price_micro_usdc": price_micro,
    }
    _uploads_table().put_item(Item=item, ConditionExpression="attribute_not_exists(upload_id)")

    return _response(
        200,
        {
            "success": True,
            "data": {
                "uploadId": upload_id,
                "uploadUrl": upload_url,
                "publicUrl": None,
                "siteUrl": None,
                "expiresAt": item["expires_at"],
                "maxSize": max_size,
                "curlExample": curl_example,
                "completion_token": completion_token,
                "list_scope_bearer": bearer,
            },
            "metadata": {
                "protocol": "x402",
                "network": _payment_config()["payment_network"],
                "price": item["price_paid"],
                "payment": {"success": True, "transactionHash": None, "status": "verified"},
            },
        },
    )


def _handle_post_complete(event: dict[str, Any]) -> dict[str, Any]:
    body = decode_json_event_body(event)
    upload_id = str(body.get("uploadId") or body.get("upload_id") or "").strip()
    token = str(body.get("completion_token") or "").strip()
    if not upload_id:
        raise BadRequestError("uploadId is required")
    if not token:
        raise BadRequestError("completion_token is required")

    resp = _uploads_table().get_item(Key={"upload_id": upload_id})
    item = resp.get("Item")
    if not isinstance(item, dict):
        return _error(404, "not_found", "Upload not found")

    if str(item.get("status") or "") != "pending":
        return _error(409, "conflict", "Upload has already been completed.")
    token_hash = _hash_token(token)
    if token_hash != str(item.get("completion_token_hash") or ""):
        return _error(401, "unauthorized", "Invalid or expired completion token.")

    bucket = str(item.get("bucket") or "").strip()
    filename = str(item.get("filename") or "").strip()
    key = str(item.get("object_key") or filename).strip()
    payer_wallet = str(item.get("payer_wallet") or "").strip()
    max_size = int(item.get("max_size") or 0)
    if not bucket or not filename or not key or not payer_wallet:
        return _error(500, "internal_error", "Upload record is invalid")

    try:
        head = s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if s3_error_code(exc) in {"404", "NoSuchKey", "NotFound"}:
            raise BadRequestError("Uploaded object not found; upload the file before completing")
        raise
    content_length = int(head.get("ContentLength") or 0)
    if content_length <= 0:
        raise BadRequestError("Uploaded object size is invalid")
    if content_length > MAX_UPLOAD_SIZE_BYTES:
        raise BadRequestError(f"Uploaded object exceeds max upload size ({MAX_UPLOAD_SIZE_BYTES} bytes)")
    if max_size > 0 and content_length > max_size:
        raise BadRequestError(f"Uploaded object exceeds tier max size ({max_size} bytes)")

    # Settle payment here (can be slow); keep this endpoint retry-safe.
    # Do this only after confirming the object exists and meets size limits to
    # avoid charging if the upload never happened.
    if not str(item.get("transaction_hash") or "").strip():
        payment_payload = item.get("payment_payload")
        payment_requirements = item.get("payment_requirements")
        if not isinstance(payment_payload, dict) or not isinstance(payment_requirements, dict):
            return _error(500, "internal_error", "Upload record missing payment context")
        try:
            settle_resp = _cdp_post(
                "/v2/x402/settle",
                {
                    "x402Version": int(payment_payload.get("x402Version") or 2),
                    "paymentPayload": _strip_nulls(payment_payload),
                    "paymentRequirements": payment_requirements,
                },
                timeout_seconds=8.0,
            )
        except SettlementPendingError:
            return _response(
                202,
                {"success": False, "error": "settlement_pending", "message": "Payment settlement pending; retry completion."},
            )
        if not bool(settle_resp.get("success")):
            return _response(
                402,
                {"error": "payment_settle_failed", "message": str(settle_resp.get("errorMessage") or "Payment settlement failed.")},
            )
        transaction_hash = str(settle_resp.get("transaction") or "").strip() or None
        try:
            _uploads_table().update_item(
                Key={"upload_id": upload_id},
                UpdateExpression="SET transaction_hash=:t, payment_status=:ps",
                ExpressionAttributeValues={":t": transaction_hash, ":ps": "settled"},
            )
        except ClientError:
            logger.exception("Failed to persist settlement result (upload_id=%s)", upload_id)

    minted = _mint_ls_web_app_url(payer_wallet=payer_wallet, location=DEFAULT_REGION)
    public_url = minted["app"]
    site_url = public_url
    try:
        _uploads_table().update_item(
            Key={"upload_id": upload_id},
            UpdateExpression="SET #s=:s, actual_size=:a, public_url=:p, site_url=:u REMOVE completion_token_hash",
            ConditionExpression="#s = :pending AND completion_token_hash = :token_hash",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "uploaded",
                ":pending": "pending",
                ":token_hash": token_hash,
                ":a": content_length,
                ":p": public_url,
                ":u": site_url,
            },
        )
    except ClientError as exc:
        if s3_error_code(exc) == "ConditionalCheckFailedException":
            return _error(409, "conflict", "Upload has already been completed.")
        raise

    record = {
        "id": upload_id,
        "filename": filename,
        "contentType": item.get("content_type"),
        "tier": item.get("tier"),
        "maxSize": max_size,
        "actualSize": content_length,
        "publicUrl": public_url,
        "status": "uploaded",
        "pricePaid": item.get("price_paid"),
        "expiresAt": item.get("expires_at"),
        "createdAt": item.get("created_at"),
    }
    return _response(200, {"success": True, "data": {"upload": record}})


def _handle_get_uploads(event: dict[str, Any]) -> dict[str, Any]:
    token = _bearer_token(event)
    if token is None:
        raise UnauthorizedError("Authorization bearer token is required")
    auth = _verify_bearer(token)
    payer_wallet = auth["payer_wallet"]

    # Query by payer wallet GSI for newest-first (created_at is ISO string).
    resp = _uploads_table().query(
        IndexName="GsiByPayerWalletCreatedAt",
        KeyConditionExpression=boto3.dynamodb.conditions.Key("payer_wallet").eq(payer_wallet),
        ScanIndexForward=False,
        Limit=100,
    )
    items = resp.get("Items") or []
    uploads: list[dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        uploads.append(
            {
                "id": it.get("upload_id"),
                "filename": it.get("filename"),
                "contentType": it.get("content_type"),
                "tier": it.get("tier"),
                "maxSize": it.get("max_size"),
                "actualSize": it.get("actual_size"),
                "publicUrl": it.get("public_url"),
                "status": it.get("status"),
                "pricePaid": it.get("price_paid"),
                "expiresAt": it.get("expires_at"),
                "createdAt": it.get("created_at"),
            }
        )
    return _response(200, {"success": True, "data": {"uploads": uploads}})


def _handle_get_download(event: dict[str, Any], *, upload_id: str) -> dict[str, Any]:
    token = _bearer_token(event)
    if token is None:
        raise UnauthorizedError("Authorization bearer token is required")
    auth = _verify_bearer(token)
    payer_wallet = auth["payer_wallet"]

    resp = _uploads_table().get_item(Key={"upload_id": upload_id})
    item = resp.get("Item")
    if not isinstance(item, dict):
        return _error(404, "not_found", "Upload not found")
    if str(item.get("payer_wallet") or "") != payer_wallet:
        raise ForbiddenError("Upload not found for this wallet")

    download_url: str | None = None
    if str(item.get("status") or "") == "uploaded":
        bucket = str(item.get("bucket") or "").strip()
        key = str(item.get("object_key") or item.get("filename") or "").strip()
        if bucket and key:
            download_url = s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": key},
                ExpiresIn=300,
            )

    record: dict[str, Any] = {
        "id": upload_id,
        "filename": item.get("filename"),
        "contentType": item.get("content_type"),
        "tier": item.get("tier"),
        "maxSize": item.get("max_size"),
        "actualSize": item.get("actual_size"),
        "publicUrl": item.get("public_url"),
        "status": item.get("status"),
        "pricePaid": item.get("price_paid"),
        "expiresAt": item.get("expires_at"),
        "createdAt": item.get("created_at"),
        "downloadUrl": download_url,
    }
    return _response(200, {"success": True, "data": {"upload": record}})

