"""
Lambda handler for POST /storage/upload.

Flow:
1. Parse request and optional Idempotency-Key.
2. Lookup and validate quote in DynamoDB.
3. Require an existing confirmed payment ledger record for (wallet_address, quote_id).
4. Upload ciphertext to wallet-scoped S3 bucket with wrapped DEK metadata.
5. Write upload transaction log row in DynamoDB.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any

import boto3
from botocore.exceptions import ClientError

try:
    from common.log_api_call_loader import load_log_api_call
    from common.request_log_utils import (
        build_log_event,
        request_id,
        request_method,
        request_path,
        sanitize_error_message,
    )
except ModuleNotFoundError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from common.log_api_call_loader import load_log_api_call
    from common.request_log_utils import (
        build_log_event,
        request_id,
        request_method,
        request_path,
        sanitize_error_message,
    )


log_api_call = load_log_api_call(emit_warning=True, logger=logging.getLogger(__name__))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
_log_event = build_log_event(logger)
_request_id = request_id
_request_method = request_method
_request_path = request_path

US_EAST_1_REGION = "us-" + "east-1"
DEFAULT_LOCATION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or US_EAST_1_REGION
DEFAULT_PROVIDER = "aws"
DEFAULT_PAYMENT_NETWORK = "eip155:8453"
DEFAULT_PAYMENT_ASSET = "0x833589fCD6EDb6E08f4C7C32D4f71b54bdA02913"
DEFAULT_RECIPIENT_WALLET = "0x47D241ae97fE37186AC59894290CA1c54c060A6c"
DEFAULT_PAYMENT_TOKEN_NAME = "USD Coin"
DEFAULT_PAYMENT_TOKEN_VERSION = "2"
USDC_DECIMALS = Decimal("1000000")

IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60
PRESIGNED_URL_EXPIRES_IN_SECONDS = 60 * 60

QUOTES_TABLE_ENV = "QUOTES_TABLE_NAME"
UPLOAD_TRANSACTION_LOG_TABLE_ENV = "UPLOAD_TRANSACTION_LOG_TABLE_NAME"
UPLOAD_IDEMPOTENCY_TABLE_ENV = "UPLOAD_IDEMPOTENCY_TABLE_NAME"
PAYMENT_LEDGER_TABLE_ENV = "PAYMENT_LEDGER_TABLE_NAME"
RELAYER_SECRET_ID_ENV = "MNEMOSPARK_RELAYER_SECRET_ID"

_RELAYER_PRIVATE_KEY_CACHE: str | None = None
_MOCK_SETTLEMENT_WARNING_EMITTED = False

# Headers are normalized to lowercase by _normalize_headers, so keep only unique keys here.
PAYMENT_SIGNATURE_HEADER_NAMES = (
    "payment-signature",
    "x-payment",
)
PAYMENT_REQUIRED_RESPONSE_HEADERS = ("PAYMENT-REQUIRED", "x-payment-required")
PAYMENT_RESPONSE_HEADERS = ("PAYMENT-RESPONSE", "x-payment-response")

ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
NONCE_PATTERN = re.compile(r"^0x[a-fA-F0-9]{64}$")

BUCKET_NAME_MIN_LEN = 3
BUCKET_NAME_MAX_LEN = 63
BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
BUCKET_FORBIDDEN_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
BUCKET_FORBIDDEN_SUFFIXES = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
BUCKET_IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

NETWORK_TO_CAIP2 = {
    "base": "eip155:8453",
    "base-mainnet": "eip155:8453",
    "eip155:8453": "eip155:8453",
    "8453": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "eip155:84532": "eip155:84532",
    "84532": "eip155:84532",
}

TRANSFER_WITH_AUTH_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}

USDC_TRANSFER_WITH_AUTHORIZATION_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "from", "type": "address"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "value", "type": "uint256"},
            {"internalType": "uint256", "name": "validAfter", "type": "uint256"},
            {"internalType": "uint256", "name": "validBefore", "type": "uint256"},
            {"internalType": "bytes32", "name": "nonce", "type": "bytes32"},
            {"internalType": "uint8", "name": "v", "type": "uint8"},
            {"internalType": "bytes32", "name": "r", "type": "bytes32"},
            {"internalType": "bytes32", "name": "s", "type": "bytes32"},
        ],
        "name": "transferWithAuthorization",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]


class BadRequestError(ValueError):
    """Raised when request validation fails."""


class ForbiddenError(ValueError):
    """Raised when authorizer wallet context is missing or mismatched."""


class NotFoundError(ValueError):
    """Raised when an expected resource is missing."""


class ConflictError(ValueError):
    """Raised for idempotency conflicts."""


@dataclass(frozen=True)
class PaymentRequiredError(Exception):
    message: str
    requirements: dict[str, Any]
    details: Any = None


@dataclass(frozen=True)
class ParsedUploadRequest:
    quote_id: str
    wallet_address: str
    object_id: str
    object_id_hash: str
    object_key: str
    provider: str
    location: str
    mode: str | None
    content_sha256: str | None
    ciphertext: bytes | None
    wrapped_dek: str
    idempotency_key: str | None
    content_length_bytes: int | None = None


@dataclass(frozen=True)
class ParsedUploadConfirmRequest:
    quote_id: str
    wallet_address: str
    object_key: str
    idempotency_key: str


@dataclass(frozen=True)
class QuoteContext:
    storage_price: Decimal
    storage_price_micro: int
    provider: str
    location: str


@dataclass(frozen=True)
class TransferAuthorization:
    signature: str
    from_address: str
    to_address: str
    value: int
    valid_after: int
    valid_before: int
    nonce: str
    network: str
    asset: str
    domain_name: str
    domain_version: str


@dataclass(frozen=True)
class PaymentVerificationResult:
    trans_id: str
    network: str
    asset: str
    amount: int


@dataclass(frozen=True)
class PaymentLedgerRecord:
    trans_id: str
    network: str
    asset: str
    amount: int
    recipient_wallet: str | None = None


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


def _error_response(
    status_code: int,
    error: str,
    message: str,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"error": error, "message": message}
    if details is not None:
        body["details"] = details
    return _response(status_code, body, headers=headers)


def _normalize_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        if isinstance(key, str) and value is not None:
            normalized[key.lower()] = str(value)
    return normalized


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


def _header_value(headers: dict[str, str], name: str) -> str | None:
    value = headers.get(name.lower())
    if value is None:
        return None
    value = value.strip()
    return value or None


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


def _collect_request_params(event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    query_params = event.get("queryStringParameters") or {}
    if not isinstance(query_params, dict):
        raise BadRequestError("queryStringParameters must be an object")

    params = {key: value for key, value in query_params.items() if value is not None}
    params.update(_decode_event_body(event))
    headers = _normalize_headers(event.get("headers"))
    return params, headers


def _require_string_field(params: dict[str, Any], field_name: str) -> str:
    value = params.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise BadRequestError(f"{field_name} is required")
    return value.strip()


def _coerce_int(value: Any, field_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise BadRequestError(f"{field_name} must be an integer") from exc


def _coerce_decimal(value: Any, field_name: str) -> Decimal:
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise BadRequestError(f"{field_name} must be numeric") from exc


def _normalize_address(value: str, field_name: str) -> str:
    candidate = value.strip()
    if not ADDRESS_PATTERN.fullmatch(candidate):
        raise BadRequestError(f"{field_name} must be a 0x-prefixed 20-byte hex address")
    return f"0x{candidate[2:].lower()}"


def _optional_normalized_address(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not ADDRESS_PATTERN.fullmatch(candidate):
        return None
    return f"0x{candidate[2:].lower()}"


def _decode_base64_field(params: dict[str, Any], field_name: str) -> bytes:
    raw = params.get(field_name)
    if not isinstance(raw, str) or not raw.strip():
        raise BadRequestError(f"{field_name} is required")
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise BadRequestError(f"{field_name} must be valid base64") from exc


def _validate_object_key(object_key: str) -> None:
    if not object_key or "/" in object_key or "\\" in object_key or object_key in {".", ".."}:
        raise BadRequestError("object_key must be a single path segment")


def _canonicalize_network(network: str) -> str:
    mapped = NETWORK_TO_CAIP2.get(network.strip().lower())
    if not mapped:
        raise BadRequestError("network must be Base mainnet or Base Sepolia (CAIP-2)")
    return mapped


def _chain_id_from_network(network: str) -> int:
    canonical = _canonicalize_network(network)
    return int(canonical.split(":")[1])


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


def _ensure_bucket_exists(s3_client: Any, bucket_name: str, location: str) -> None:
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        return
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        # Treat 400/BadRequest the same as 404-style "bucket does not exist" responses so we
        # can proceed to create the bucket. This is observed when a previously deleted bucket
        # name is probed shortly after deletion.
        if error_code not in {"404", "NotFound", "NoSuchBucket", "400", "BadRequest"}:
            if error_code in {"403", "Forbidden"}:
                logger.warning(
                    "HeadBucket 403 for %s: ensure bucket is in this account and Lambda role has s3:ListBucket on mnemospark-*",
                    bucket_name,
                )
            raise

    normalized_location = (location or "").strip()
    # S3 CreateBucket for [REDACTED] must omit LocationConstraint.
    if not normalized_location or normalized_location == US_EAST_1_REGION:
        s3_client.create_bucket(Bucket=bucket_name)
    else:
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": normalized_location},
        )


def _presigned_put_object_params(
    bucket_name: str, object_key: str, wrapped_dek: str, content_length_bytes: int | None = None
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "Bucket": bucket_name,
        "Key": object_key,
        "Metadata": {"wrapped-dek": wrapped_dek},
    }
    if content_length_bytes is not None:
        params["ContentLength"] = content_length_bytes
    return params


def parse_input(event: dict[str, Any]) -> ParsedUploadRequest:
    params, headers = _collect_request_params(event)
    quote_id = _require_string_field(params, "quote_id")
    wallet_address = _normalize_address(_require_string_field(params, "wallet_address"), "wallet_address")
    object_id = _require_string_field(params, "object_id")
    object_id_hash = _require_string_field(params, "object_id_hash")

    object_key = str(params.get("object_key") or object_id).strip()
    _validate_object_key(object_key)

    provider = str(params.get("provider") or DEFAULT_PROVIDER).strip() or DEFAULT_PROVIDER
    location = str(params.get("location") or params.get("region") or DEFAULT_LOCATION).strip() or DEFAULT_LOCATION

    raw_mode = params.get("mode")
    if raw_mode is None:
        mode = "inline"
    elif not isinstance(raw_mode, str):
        raise BadRequestError("mode must be a string")
    else:
        mode = raw_mode.strip().lower() or "inline"
    if mode not in {"inline", "presigned"}:
        raise BadRequestError("mode must be either 'inline' or 'presigned'")

    content_sha256: str | None = None
    raw_content_sha256 = params.get("content_sha256")
    if raw_content_sha256 is not None:
        if not isinstance(raw_content_sha256, str):
            raise BadRequestError("content_sha256 must be a string")
        content_sha256 = raw_content_sha256.strip() or None

    content_length_bytes: int | None = None
    raw_content_length = params.get("content_length_bytes")
    if raw_content_length is not None:
        content_length_bytes = _coerce_int(raw_content_length, "content_length_bytes")
        if content_length_bytes < 0:
            raise BadRequestError("content_length_bytes must be greater than or equal to 0")

    ciphertext: bytes | None = None
    has_ciphertext_field = "ciphertext" in params or "content" in params
    if mode == "inline" or has_ciphertext_field:
        ciphertext_field = "ciphertext"
        if "ciphertext" not in params and "content" in params:
            ciphertext_field = "content"
        ciphertext = _decode_base64_field(params, ciphertext_field)

    wrapped_dek = str(params.get("wrapped_dek") or params.get("wrapped-dek") or "").strip()
    if not wrapped_dek:
        raise BadRequestError("wrapped_dek is required")
    try:
        base64.b64decode(wrapped_dek, validate=True)
    except Exception as exc:
        raise BadRequestError("wrapped_dek must be valid base64") from exc

    idempotency_key = _header_value(headers, "Idempotency-Key")
    if mode == "presigned" and not idempotency_key:
        raise BadRequestError("Idempotency-Key header is required for presigned mode")
    return ParsedUploadRequest(
        quote_id=quote_id,
        wallet_address=wallet_address,
        object_id=object_id,
        object_id_hash=object_id_hash,
        object_key=object_key,
        provider=provider,
        location=location,
        mode=mode,
        content_sha256=content_sha256,
        ciphertext=ciphertext,
        wrapped_dek=wrapped_dek,
        idempotency_key=idempotency_key,
        content_length_bytes=content_length_bytes,
    )


def parse_confirm_input(event: dict[str, Any]) -> ParsedUploadConfirmRequest:
    params = _decode_event_body(event)
    quote_id = _require_string_field(params, "quote_id")
    wallet_address = _normalize_address(_require_string_field(params, "wallet_address"), "wallet_address")
    object_key = _require_string_field(params, "object_key")
    _validate_object_key(object_key)
    idempotency_key = _require_string_field(params, "idempotency_key")
    return ParsedUploadConfirmRequest(
        quote_id=quote_id,
        wallet_address=wallet_address,
        object_key=object_key,
        idempotency_key=idempotency_key,
    )


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return value


def _resolve_relayer_private_key() -> str:
    global _RELAYER_PRIVATE_KEY_CACHE
    if _RELAYER_PRIVATE_KEY_CACHE:
        return _RELAYER_PRIVATE_KEY_CACHE

    secret_id = _require_env(RELAYER_SECRET_ID_ENV)
    try:
        secret_response = boto3.client("secretsmanager").get_secret_value(SecretId=secret_id)
    except ClientError as exc:
        raise RuntimeError("Unable to retrieve relayer private key from Secrets Manager") from exc

    relayer_private_key = ""
    secret_string = secret_response.get("SecretString")
    if isinstance(secret_string, str):
        relayer_private_key = secret_string.strip()
    elif "SecretBinary" in secret_response:
        secret_binary = secret_response.get("SecretBinary")
        if isinstance(secret_binary, str):
            try:
                secret_binary_bytes = base64.b64decode(secret_binary)
            except Exception as exc:
                raise RuntimeError("Relayer secret payload is invalid") from exc
        elif isinstance(secret_binary, (bytes, bytearray)):
            secret_binary_bytes = bytes(secret_binary)
        else:
            raise RuntimeError("Relayer secret payload is invalid")

        try:
            relayer_private_key = secret_binary_bytes.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise RuntimeError("Relayer secret payload is invalid") from exc

    if not relayer_private_key:
        raise RuntimeError("Relayer secret payload is empty")

    _RELAYER_PRIVATE_KEY_CACHE = relayer_private_key
    return relayer_private_key


def _build_quote_context(quote_item: dict[str, Any] | None, request: ParsedUploadRequest, now: int) -> QuoteContext:
    if not quote_item:
        raise NotFoundError("quote_not_found")

    expires_at_raw = quote_item.get("expires_at")
    if expires_at_raw is None:
        raise NotFoundError("quote_not_found")
    expires_at = _coerce_int(expires_at_raw, "quote.expires_at")
    if expires_at <= now:
        raise NotFoundError("quote_not_found")

    quote_object_hash = str(quote_item.get("object_id_hash") or "").strip()
    if not quote_object_hash or quote_object_hash != request.object_id_hash:
        raise BadRequestError("object_id_hash does not match the quote")

    quote_object_id = str(quote_item.get("object_id") or "").strip()
    if quote_object_id and quote_object_id != request.object_id:
        raise BadRequestError("object_id does not match the quote")

    quote_addr = _optional_normalized_address(quote_item.get("addr") or quote_item.get("wallet_address"))
    if quote_addr and quote_addr != request.wallet_address:
        raise BadRequestError("wallet_address does not match the quote")

    storage_price = _coerce_decimal(quote_item.get("storage_price"), "quote.storage_price")
    if storage_price <= 0:
        raise BadRequestError("quote.storage_price must be greater than 0")

    provider = str(quote_item.get("provider") or request.provider).strip() or request.provider
    location = str(
        quote_item.get("location") or quote_item.get("region") or request.location
    ).strip() or request.location
    storage_price_micro = int(
        (storage_price * USDC_DECIMALS).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )

    return QuoteContext(
        storage_price=storage_price,
        storage_price_micro=storage_price_micro,
        provider=provider,
        location=location,
    )


def _payment_config() -> dict[str, str]:
    recipient_wallet_raw = os.environ.get("MNEMOSPARK_RECIPIENT_WALLET", DEFAULT_RECIPIENT_WALLET)
    payment_asset_raw = os.environ.get("MNEMOSPARK_PAYMENT_ASSET", DEFAULT_PAYMENT_ASSET)
    payment_network_raw = os.environ.get("MNEMOSPARK_PAYMENT_NETWORK", DEFAULT_PAYMENT_NETWORK)
    try:
        recipient_wallet = _normalize_address(recipient_wallet_raw, "MNEMOSPARK_RECIPIENT_WALLET")
        payment_asset = _normalize_address(payment_asset_raw, "MNEMOSPARK_PAYMENT_ASSET")
        payment_network = _canonicalize_network(payment_network_raw)
    except BadRequestError as exc:
        raise RuntimeError(str(exc)) from exc

    return {
        "recipient_wallet": recipient_wallet,
        "payment_asset": payment_asset,
        "payment_network": payment_network,
        "token_name": os.environ.get("MNEMOSPARK_PAYMENT_TOKEN_NAME", DEFAULT_PAYMENT_TOKEN_NAME),
        "token_version": os.environ.get("MNEMOSPARK_PAYMENT_TOKEN_VERSION", DEFAULT_PAYMENT_TOKEN_VERSION),
    }


def _encode_json_base64(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(encoded).decode("ascii")


def _payment_requirements(quote_context: QuoteContext, payment_config: dict[str, str]) -> dict[str, Any]:
    """Build x402 Payment-Required payload. Client expects { accepts: [ PaymentOption ] }."""
    option: dict[str, Any] = {
        "scheme": "exact",
        "network": payment_config["payment_network"],
        "asset": payment_config["payment_asset"],
        "payTo": payment_config["recipient_wallet"],
        "amount": str(quote_context.storage_price_micro),
        "extra": {
            "name": payment_config["token_name"],
            "version": payment_config["token_version"],
        },
    }
    return {"accepts": [option]}


def _payment_required_headers(requirements: dict[str, Any]) -> dict[str, str]:
    encoded = _encode_json_base64(requirements)
    return {header_name: encoded for header_name in PAYMENT_REQUIRED_RESPONSE_HEADERS}


def _payment_response_headers(payment_response_header: str) -> dict[str, str]:
    return {header_name: payment_response_header for header_name in PAYMENT_RESPONSE_HEADERS}


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
    raise BadRequestError("payment signature header must be base64-encoded JSON")


def _normalize_nonce(nonce: Any) -> str:
    if not isinstance(nonce, str):
        raise BadRequestError("payment nonce must be a hex string")
    normalized = nonce.strip()
    if not NONCE_PATTERN.fullmatch(normalized):
        raise BadRequestError("payment nonce must be 32 bytes hex (0x-prefixed)")
    return f"0x{normalized[2:].lower()}"


def _extract_transfer_authorization(payment_payload: dict[str, Any]) -> TransferAuthorization:
    payload_obj = payment_payload.get("payload")
    signature = payment_payload.get("signature")
    authorization = payment_payload.get("authorization")

    if isinstance(payload_obj, dict):
        signature = signature or payload_obj.get("signature")
        authorization = authorization or payload_obj.get("authorization") or payload_obj.get("transferWithAuthorization")

    accepted = payment_payload.get("accepted")
    accepted_obj: dict[str, Any] = {}
    if isinstance(accepted, list):
        for candidate in accepted:
            if isinstance(candidate, dict):
                accepted_obj = candidate
                break
    elif isinstance(accepted, dict):
        accepted_obj = accepted

    if not isinstance(authorization, dict):
        raise BadRequestError("payment authorization payload is missing authorization fields")
    if not isinstance(signature, str) or not signature.strip():
        raise BadRequestError("payment signature is required")

    signature = signature.strip()
    if not signature.startswith("0x") or len(signature) != 132:
        raise BadRequestError("payment signature must be a 65-byte hex string")

    def _raw_or_fallback(key: str, fallback_key: str | None = None) -> Any:
        if key in authorization and authorization[key] not in (None, ""):
            return authorization[key]
        if fallback_key and fallback_key in accepted_obj and accepted_obj[fallback_key] not in (None, ""):
            return accepted_obj[fallback_key]
        return None

    from_address = _normalize_address(str(_raw_or_fallback("from") or ""), "payment authorization from")
    to_address = _normalize_address(str(_raw_or_fallback("to", "payTo") or ""), "payment authorization to")
    value_raw = _raw_or_fallback("value", "amount")
    if value_raw in (None, ""):
        value_raw = accepted_obj.get("maxAmountRequired")
    value = _coerce_int(value_raw, "payment authorization value")
    valid_after = _coerce_int(_raw_or_fallback("validAfter"), "payment authorization validAfter")
    valid_before = _coerce_int(_raw_or_fallback("validBefore"), "payment authorization validBefore")
    nonce = _normalize_nonce(_raw_or_fallback("nonce"))

    network_raw = (
        str(_raw_or_fallback("network", "network") or payment_payload.get("network") or DEFAULT_PAYMENT_NETWORK)
        .strip()
    )
    network = _canonicalize_network(network_raw)
    asset_raw = str(_raw_or_fallback("asset", "asset") or payment_payload.get("asset") or DEFAULT_PAYMENT_ASSET).strip()
    asset = _normalize_address(asset_raw, "payment asset")

    extra = accepted_obj.get("extra") if isinstance(accepted_obj.get("extra"), dict) else {}
    domain_name = str(
        authorization.get("name")
        or extra.get("name")
        or payment_payload.get("tokenName")
        or DEFAULT_PAYMENT_TOKEN_NAME
    )
    domain_version = str(
        authorization.get("version")
        or extra.get("version")
        or payment_payload.get("tokenVersion")
        or DEFAULT_PAYMENT_TOKEN_VERSION
    )

    return TransferAuthorization(
        signature=signature,
        from_address=from_address,
        to_address=to_address,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
        network=network,
        asset=asset,
        domain_name=domain_name,
        domain_version=domain_version,
    )


def _recover_authorization_signer(authorization: TransferAuthorization) -> str:
    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data
    except ImportError as exc:  # pragma: no cover - runtime dependency guard
        raise RuntimeError("eth-account dependency is required for EIP-712 verification") from exc

    signable = encode_typed_data(
        domain_data={
            "name": authorization.domain_name,
            "version": authorization.domain_version,
            "chainId": _chain_id_from_network(authorization.network),
            "verifyingContract": authorization.asset,
        },
        message_types=TRANSFER_WITH_AUTH_TYPES,
        message_data={
            "from": authorization.from_address,
            "to": authorization.to_address,
            "value": int(authorization.value),
            "validAfter": int(authorization.valid_after),
            "validBefore": int(authorization.valid_before),
            "nonce": authorization.nonce,
        },
    )
    signer = Account.recover_message(signable, signature=authorization.signature)
    return _normalize_address(signer, "recovered signer")


def _split_signature(signature: str) -> tuple[int, bytes, bytes]:
    raw = bytes.fromhex(signature[2:])
    if len(raw) != 65:
        raise BadRequestError("payment signature must be exactly 65 bytes")
    r = raw[:32]
    s = raw[32:64]
    v = raw[64]
    if v < 27:
        v += 27
    return v, r, s


def _mock_settlement_tx_id(quote_id: str, authorization: TransferAuthorization) -> str:
    digest = hashlib.sha256(
        f"{quote_id}:{authorization.signature}:{authorization.nonce}:{authorization.value}".encode("utf-8")
    ).hexdigest()
    return f"0x{digest[:64]}"


def _settlement_mode() -> str:
    return os.environ.get("MNEMOSPARK_PAYMENT_SETTLEMENT_MODE", "onchain").strip().lower() or "onchain"


def _emit_mock_settlement_warning_once(settlement_mode: str) -> None:
    global _MOCK_SETTLEMENT_WARNING_EMITTED
    if settlement_mode != "mock" or _MOCK_SETTLEMENT_WARNING_EMITTED:
        return
    _log_event(
        logging.WARNING,
        "mock_settlement_mode_active",
        message=(
            "Payment settlement is in MOCK mode. No real USDC transfers will occur. "
            "Set MNEMOSPARK_PAYMENT_SETTLEMENT_MODE=onchain for production."
        ),
    )
    _MOCK_SETTLEMENT_WARNING_EMITTED = True


def _onchain_settle_payment(authorization: TransferAuthorization) -> str:
    try:
        from eth_account import Account
        from web3 import Web3
    except ImportError as exc:  # pragma: no cover - runtime dependency guard
        raise RuntimeError("web3 and eth-account dependencies are required for on-chain settlement") from exc

    rpc_url = os.environ.get("MNEMOSPARK_BASE_RPC_URL", "").strip()
    if not rpc_url:
        raise RuntimeError("MNEMOSPARK_BASE_RPC_URL is required for on-chain settlement mode")
    relayer_private_key = _resolve_relayer_private_key()

    web3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20}))
    if not web3.is_connected():
        raise RuntimeError("Unable to connect to Base RPC endpoint")

    relayer = Account.from_key(relayer_private_key)
    contract = web3.eth.contract(
        address=Web3.to_checksum_address(authorization.asset),
        abi=USDC_TRANSFER_WITH_AUTHORIZATION_ABI,
    )
    nonce_bytes = bytes.fromhex(authorization.nonce[2:])
    v, r, s = _split_signature(authorization.signature)

    gas_limit = int(os.environ.get("MNEMOSPARK_SETTLEMENT_GAS_LIMIT", "220000"))
    gas_price = web3.eth.gas_price
    tx = contract.functions.transferWithAuthorization(
        Web3.to_checksum_address(authorization.from_address),
        Web3.to_checksum_address(authorization.to_address),
        int(authorization.value),
        int(authorization.valid_after),
        int(authorization.valid_before),
        nonce_bytes,
        v,
        r,
        s,
    ).build_transaction(
        {
            "from": relayer.address,
            "chainId": _chain_id_from_network(authorization.network),
            "nonce": web3.eth.get_transaction_count(relayer.address),
            "gas": gas_limit,
            "gasPrice": gas_price,
        }
    )

    signed_tx = web3.eth.account.sign_transaction(tx, private_key=relayer_private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    if getattr(receipt, "status", 0) != 1:
        raise RuntimeError("USDC transferWithAuthorization transaction failed")
    return tx_hash.hex()


def verify_and_settle_payment(
    payment_header: str | None,
    wallet_address: str,
    quote_id: str,
    expected_amount: int,
    expected_recipient: str,
    expected_network: str,
    expected_asset: str,
    requirements: dict[str, Any],
) -> PaymentVerificationResult:
    if not payment_header:
        raise PaymentRequiredError(
            message="Payment authorization header is required",
            requirements=requirements,
        )

    try:
        payment_payload = _decode_payment_payload(payment_header)
        authorization = _extract_transfer_authorization(payment_payload)
    except BadRequestError as exc:
        raise PaymentRequiredError(
            message="Payment authorization is invalid",
            requirements=requirements,
            details=str(exc),
        ) from exc

    if authorization.from_address != wallet_address:
        raise PaymentRequiredError(
            message="Payment signer does not match wallet_address",
            requirements=requirements,
        )
    if authorization.to_address != expected_recipient:
        raise PaymentRequiredError(
            message="Payment recipient does not match configured recipient wallet",
            requirements=requirements,
        )
    if authorization.asset != expected_asset:
        raise PaymentRequiredError(
            message="Payment asset does not match configured asset",
            requirements=requirements,
        )
    if authorization.network != expected_network:
        raise PaymentRequiredError(
            message="Payment network does not match configured Base network",
            requirements=requirements,
        )
    if authorization.value < expected_amount:
        raise PaymentRequiredError(
            message="Payment amount is lower than the quote amount",
            requirements=requirements,
        )

    now = int(time.time())
    if authorization.valid_after > now:
        raise PaymentRequiredError(
            message="Payment authorization is not yet valid",
            requirements=requirements,
        )
    if authorization.valid_before <= now:
        raise PaymentRequiredError(
            message="Payment authorization has expired",
            requirements=requirements,
        )

    try:
        recovered_signer = _recover_authorization_signer(authorization)
    except Exception as exc:
        raise PaymentRequiredError(
            message="EIP-712 signature verification failed",
            requirements=requirements,
            details=str(exc),
        ) from exc

    if recovered_signer != wallet_address:
        raise PaymentRequiredError(
            message="EIP-712 signature does not recover wallet_address",
            requirements=requirements,
        )

    settlement_mode = _settlement_mode()
    if settlement_mode == "mock":
        trans_id = _mock_settlement_tx_id(quote_id, authorization)
    elif settlement_mode == "onchain":
        trans_id = _onchain_settle_payment(authorization)
    else:
        raise RuntimeError("MNEMOSPARK_PAYMENT_SETTLEMENT_MODE must be either mock or onchain")

    return PaymentVerificationResult(
        trans_id=trans_id,
        network=authorization.network,
        asset=authorization.asset,
        amount=authorization.value,
    )


def _request_fingerprint(request: ParsedUploadRequest) -> str:
    ciphertext_sha256 = request.content_sha256
    if request.ciphertext is not None:
        ciphertext_sha256 = hashlib.sha256(request.ciphertext).hexdigest()

    normalized_mode = (request.mode or "").strip().lower()
    stable_payload = {
        "quote_id": request.quote_id,
        "wallet_address": request.wallet_address,
        "object_id": request.object_id,
        "object_id_hash": request.object_id_hash,
        "object_key": request.object_key,
        "provider": request.provider,
        "location": request.location,
        "wrapped_dek": request.wrapped_dek,
        "ciphertext_sha256": ciphertext_sha256 or "",
    }
    # Keep legacy fingerprint compatibility for inline uploads.
    if normalized_mode and normalized_mode != "inline":
        stable_payload["mode"] = normalized_mode
        if request.content_length_bytes is not None:
            stable_payload["content_length_bytes"] = request.content_length_bytes
    encoded = json.dumps(stable_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _confirm_request_fingerprint(
    quote_id: str,
    wallet_address: str,
    object_key: str,
) -> str:
    stable_payload = {
        "quote_id": quote_id,
        "wallet_address": wallet_address,
        "object_key": object_key,
    }
    encoded = json.dumps(stable_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_retryable_upload_after_payment_idempotency(item: dict[str, Any]) -> bool:
    status = str(item.get("status") or "").lower()
    return status == "in_progress" and item.get("upload_retry_after_payment") is True


def _fetch_existing_idempotency(
    idempotency_table: Any,
    idempotency_key: str,
    request_hash: str,
    now: int,
) -> dict[str, Any] | None:
    for _ in range(3):
        response = idempotency_table.get_item(
            Key={"idempotency_key": idempotency_key},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not item:
            return None

        expires_at = _coerce_int(item.get("expires_at"), "idempotency.expires_at")
        if expires_at <= now:
            try:
                idempotency_table.delete_item(
                    Key={"idempotency_key": idempotency_key},
                    ConditionExpression="expires_at <= :now",
                    ExpressionAttributeValues={":now": now},
                )
                return None
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code")
                if error_code != "ConditionalCheckFailedException":
                    raise
                # Another writer updated this key between get_item and delete_item.
                continue

        stored_hash = str(item.get("request_hash") or "")
        if stored_hash and stored_hash != request_hash:
            raise ConflictError("Idempotency-Key cannot be reused with a different request payload")

        status = str(item.get("status") or "").lower()
        if status == "completed":
            return item
        if status == "pending_confirmation":
            return item
        if status == "in_progress":
            if _is_retryable_upload_after_payment_idempotency(item):
                return item
            raise ConflictError("Upload is already in progress for this Idempotency-Key")

        raise ConflictError("Idempotency-Key is in an unknown state")

    raise ConflictError("Idempotency-Key state changed concurrently; please retry")


def _claim_idempotency_lock(
    idempotency_table: Any,
    idempotency_key: str,
    request_hash: str,
    now: int,
) -> dict[str, Any] | None:
    lock_item = {
        "idempotency_key": idempotency_key,
        "status": "in_progress",
        "request_hash": request_hash,
        "created_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        "expires_at": now + IDEMPOTENCY_TTL_SECONDS,
    }

    for _ in range(2):
        try:
            idempotency_table.put_item(
                Item=lock_item,
                ConditionExpression="attribute_not_exists(idempotency_key)",
            )
            return None
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")
            if error_code != "ConditionalCheckFailedException":
                raise
            existing_item = _fetch_existing_idempotency(
                idempotency_table=idempotency_table,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                now=now,
            )
            if existing_item:
                return existing_item
    raise ConflictError("Upload is already in progress for this Idempotency-Key")


def _mark_idempotency_completed(
    idempotency_table: Any,
    idempotency_key: str,
    request_hash: str,
    response_body: dict[str, Any],
    payment_response_header: str,
    now: int,
) -> None:
    idempotency_table.put_item(
        Item={
            "idempotency_key": idempotency_key,
            "status": "completed",
            "request_hash": request_hash,
            "response_body": json.dumps(response_body, sort_keys=True),
            "payment_response": payment_response_header,
            "completed_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "expires_at": now + IDEMPOTENCY_TTL_SECONDS,
        }
    )


def _mark_idempotency_pending_confirmation(
    idempotency_table: Any,
    idempotency_key: str,
    request_hash: str,
    confirm_request_hash: str,
    response_body: dict[str, Any],
    payment_response_header: str,
    payment_result: PaymentVerificationResult,
    quote_context: QuoteContext,
    now: int,
) -> None:
    idempotency_table.put_item(
        Item={
            "idempotency_key": idempotency_key,
            "status": "pending_confirmation",
            "request_hash": request_hash,
            "confirm_request_hash": confirm_request_hash,
            "response_body": json.dumps(response_body, sort_keys=True),
            "payment_response": payment_response_header,
            "payment_trans_id": payment_result.trans_id,
            "payment_network": payment_result.network,
            "payment_asset": payment_result.asset,
            "payment_amount": str(payment_result.amount),
            "quote_storage_price": str(quote_context.storage_price),
            "quote_provider": quote_context.provider,
            "quote_location": quote_context.location,
            "updated_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "expires_at": now + IDEMPOTENCY_TTL_SECONDS,
        }
    )


def _mark_idempotency_upload_retryable(
    idempotency_table: Any,
    idempotency_key: str,
    request_hash: str,
    payment_result: PaymentVerificationResult,
    quote_context: QuoteContext,
    now: int,
) -> None:
    try:
        idempotency_table.put_item(
            Item={
                "idempotency_key": idempotency_key,
                "status": "in_progress",
                "request_hash": request_hash,
                "upload_retry_after_payment": True,
                "payment_trans_id": payment_result.trans_id,
                "payment_network": payment_result.network,
                "payment_asset": payment_result.asset,
                "payment_amount": str(payment_result.amount),
                "quote_storage_price": str(quote_context.storage_price),
                "quote_provider": quote_context.provider,
                "quote_location": quote_context.location,
                "updated_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
                "expires_at": now + IDEMPOTENCY_TTL_SECONDS,
            },
            ConditionExpression="attribute_not_exists(idempotency_key) OR status <> :completed_status",
            ExpressionAttributeValues={":completed_status": "completed"},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise


def _payment_result_from_retryable_idempotency(item: dict[str, Any]) -> PaymentVerificationResult:
    trans_id = str(item.get("payment_trans_id") or "").strip()
    network = str(item.get("payment_network") or "").strip()
    asset = str(item.get("payment_asset") or "").strip()
    amount_raw = item.get("payment_amount")
    try:
        amount = int(amount_raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Stored retryable idempotency payment amount is invalid") from exc

    if not trans_id or not network or not asset or amount <= 0:
        raise RuntimeError("Stored retryable idempotency payment context is invalid")

    return PaymentVerificationResult(
        trans_id=trans_id,
        network=network,
        asset=asset,
        amount=amount,
    )


def _quote_context_from_retryable_idempotency(item: dict[str, Any]) -> QuoteContext:
    storage_price_raw = item.get("quote_storage_price")
    provider = str(item.get("quote_provider") or "").strip()
    location = str(item.get("quote_location") or "").strip()
    try:
        storage_price = Decimal(str(storage_price_raw))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise RuntimeError("Stored retryable idempotency quote storage_price is invalid") from exc

    if storage_price <= 0 or not provider or not location:
        raise RuntimeError("Stored retryable idempotency quote context is invalid")

    storage_price_micro = int(
        (storage_price * USDC_DECIMALS).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )
    return QuoteContext(
        storage_price=storage_price,
        storage_price_micro=storage_price_micro,
        provider=provider,
        location=location,
    )


def _load_confirmed_payment_record(
    payment_ledger_table: Any,
    request: ParsedUploadRequest,
    requirements: dict[str, Any],
) -> PaymentLedgerRecord:
    payment_item = payment_ledger_table.get_item(
        Key={
            "wallet_address": request.wallet_address,
            "quote_id": request.quote_id,
        },
        ConsistentRead=True,
    ).get("Item")
    if not payment_item:
        raise PaymentRequiredError(
            message="Confirmed payment record is required before upload",
            requirements=requirements,
            details={
                "quote_id": request.quote_id,
                "wallet_address": request.wallet_address,
                "reason": "payment_record_missing",
                "settle_path": "/payment/settle",
            },
        )

    payment_status = str(payment_item.get("payment_status") or "").strip().lower()
    if payment_status != "confirmed":
        raise PaymentRequiredError(
            message="Payment record is not confirmed for this quote",
            requirements=requirements,
            details={
                "quote_id": request.quote_id,
                "wallet_address": request.wallet_address,
                "reason": "payment_not_confirmed",
                "payment_status": payment_status or None,
                "settle_path": "/payment/settle",
            },
        )

    ledger_wallet_address = _optional_normalized_address(payment_item.get("wallet_address"))
    if ledger_wallet_address and ledger_wallet_address != request.wallet_address:
        raise PaymentRequiredError(
            message="Payment record wallet does not match upload wallet",
            requirements=requirements,
            details={
                "quote_id": request.quote_id,
                "wallet_address": request.wallet_address,
                "reason": "payment_wallet_mismatch",
                "settle_path": "/payment/settle",
            },
        )

    ledger_quote_id = str(payment_item.get("quote_id") or "").strip()
    if ledger_quote_id and ledger_quote_id != request.quote_id:
        raise PaymentRequiredError(
            message="Payment record quote_id does not match upload quote",
            requirements=requirements,
            details={
                "quote_id": request.quote_id,
                "wallet_address": request.wallet_address,
                "reason": "payment_quote_mismatch",
                "settle_path": "/payment/settle",
            },
        )

    trans_id = str(payment_item.get("trans_id") or "").strip()
    network = str(payment_item.get("network") or payment_item.get("payment_network") or "").strip()
    asset = str(payment_item.get("asset") or payment_item.get("payment_asset") or "").strip()
    amount_raw = payment_item.get("amount") or payment_item.get("payment_amount")
    try:
        amount = int(amount_raw)
    except (TypeError, ValueError) as exc:
        raise PaymentRequiredError(
            message="Payment record is malformed",
            requirements=requirements,
            details={
                "quote_id": request.quote_id,
                "wallet_address": request.wallet_address,
                "reason": "payment_amount_invalid",
                "settle_path": "/payment/settle",
            },
        ) from exc

    if not trans_id or not network or not asset or amount <= 0:
        raise PaymentRequiredError(
            message="Payment record is incomplete",
            requirements=requirements,
            details={
                "quote_id": request.quote_id,
                "wallet_address": request.wallet_address,
                "reason": "payment_record_incomplete",
                "settle_path": "/payment/settle",
            },
        )

    recipient_wallet = _optional_normalized_address(payment_item.get("recipient_wallet"))
    return PaymentLedgerRecord(
        trans_id=trans_id,
        network=network,
        asset=asset,
        amount=amount,
        recipient_wallet=recipient_wallet,
    )


def _release_idempotency_lock(idempotency_table: Any, idempotency_key: str) -> None:
    try:
        idempotency_table.delete_item(Key={"idempotency_key": idempotency_key})
    except Exception:
        # Best-effort release; lock naturally expires via TTL if delete fails.
        return


def _cached_success_response(
    idempotency_item: dict[str, Any],
    request: ParsedUploadRequest | None = None,
) -> dict[str, Any]:
    response_body_raw = idempotency_item.get("response_body")
    if not isinstance(response_body_raw, str):
        raise RuntimeError("Stored idempotency response_body is invalid")
    response_body = json.loads(response_body_raw)
    if isinstance(response_body, dict) and request is not None and "upload_url" in response_body:
        s3_client = boto3.client("s3", region_name=str(response_body.get("location") or request.location))
        response_body["upload_url"] = s3_client.generate_presigned_url(
            "put_object",
            Params=_presigned_put_object_params(
                bucket_name=str(response_body.get("bucket_name") or _bucket_name(request.wallet_address)),
                object_key=str(response_body.get("object_key") or request.object_key),
                wrapped_dek=request.wrapped_dek,
                content_length_bytes=request.content_length_bytes,
            ),
            ExpiresIn=PRESIGNED_URL_EXPIRES_IN_SECONDS,
        )
    headers: dict[str, str] = {}
    payment_response = idempotency_item.get("payment_response")
    if isinstance(payment_response, str) and payment_response:
        headers.update(_payment_response_headers(payment_response))
    return _response(200, response_body, headers=headers)


def _upload_ciphertext_to_s3(
    wallet_address: str,
    object_key: str,
    ciphertext: bytes,
    wrapped_dek: str,
    location: str,
) -> str:
    s3_client = boto3.client("s3", region_name=location)
    bucket_name = _bucket_name(wallet_address)
    _validate_bucket_name(bucket_name)
    _ensure_bucket_exists(s3_client, bucket_name, location)
    s3_client.put_object(
        Bucket=bucket_name,
        Key=object_key,
        Body=ciphertext,
        Metadata={"wrapped-dek": wrapped_dek},
    )
    return bucket_name


def _write_transaction_log(
    transaction_log_table: Any,
    now: int,
    request: ParsedUploadRequest,
    quote_context: QuoteContext,
    payment_result: PaymentVerificationResult,
    recipient_wallet: str | None,
    trans_id: str,
    bucket_name: str,
) -> None:
    timestamp = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    payment_received_at = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
    payment_asset = (
        payment_result.asset.lower()
        if isinstance(payment_result.asset, str)
        else str(payment_result.asset)
    )
    try:
        transaction_log_table.put_item(
            Item={
                # Housekeeping depends on this schema: payment_status/trans_id/payment_received_at
                # plus recipient_wallet/location/bucket_name/object_key for billing enforcement.
                "quote_id": request.quote_id,
                "trans_id": trans_id,
                "timestamp": timestamp,
                "payment_received_at": payment_received_at,
                "payment_status": "confirmed",
                "recipient_wallet": recipient_wallet or "",
                "payment_network": payment_result.network,
                "payment_asset": payment_asset,
                "payment_amount": str(payment_result.amount),
                "addr": request.wallet_address,
                "addr_hash": _wallet_hash(request.wallet_address),
                "storage_price": quote_context.storage_price,
                "object_id": request.object_id,
                "object_key": request.object_key,
                "provider": quote_context.provider,
                "bucket_name": bucket_name,
                "location": quote_context.location,
                "idempotency_key": request.idempotency_key or "",
            },
            ConditionExpression="attribute_not_exists(quote_id)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise


def _log_api_call_result(
    event: dict[str, Any],
    context: Any,
    *,
    route: str,
    status_code: int,
    result: str,
    error_code: str | None = None,
    error_message: str | None = None,
    request: ParsedUploadRequest | ParsedUploadConfirmRequest | None = None,
    quote_id: str | None = None,
    trans_id: str | None = None,
    payment_id: str | None = None,
    idempotency_key: str | None = None,
) -> None:
    wallet_address = getattr(request, "wallet_address", None) if request is not None else None
    object_id = getattr(request, "object_id", None) if request is not None else None
    object_key = getattr(request, "object_key", None) if request is not None else None
    sanitized_error_message = sanitize_error_message(error_message)
    resolved_quote_id = quote_id or (getattr(request, "quote_id", None) if request is not None else None)
    resolved_idempotency_key = idempotency_key or (
        getattr(request, "idempotency_key", None) if request is not None else None
    )
    level = logging.INFO
    if status_code >= 500:
        level = logging.ERROR
    elif status_code >= 400:
        level = logging.WARNING
    _log_event(
        level,
        "storage_upload_api_result",
        request_id=_request_id(event, context),
        method=_request_method(event),
        path=_request_path(event, route),
        status=status_code,
        result=result,
        error_code=error_code,
        error_message=sanitized_error_message,
        wallet_address=wallet_address,
        quote_id=resolved_quote_id,
        trans_id=trans_id,
        object_id=object_id,
        object_key=object_key,
        idempotency_key=resolved_idempotency_key,
    )

    log_api_call(
        event=event,
        context=context,
        route=route,
        status_code=status_code,
        result=result,
        error_code=error_code,
        error_message=error_message,
        wallet_address=wallet_address,
        quote_id=resolved_quote_id,
        trans_id=trans_id,
        payment_id=payment_id,
        object_id=object_id,
        object_key=object_key,
        idempotency_key=resolved_idempotency_key,
    )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    idempotency_lock_acquired = False
    idempotency_table: Any | None = None
    idempotency_key: str | None = None
    request_hash: str | None = None
    request: ParsedUploadRequest | None = None
    resume_upload_after_payment = False
    retryable_idempotency_item: dict[str, Any] | None = None

    try:
        now = int(time.time())
        request = parse_input(event)
        _log_event(
            logging.INFO,
            "upload_request_parsed",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event, "/storage/upload"),
            quote_id=request.quote_id,
            wallet_address=request.wallet_address,
            object_id=request.object_id,
            mode=request.mode,
        )
        _require_authorized_wallet(event, request.wallet_address)
        _log_event(
            logging.DEBUG,
            "authorized_wallet_confirmed",
            wallet_address=request.wallet_address,
        )
        request_hash = _request_fingerprint(request)
        idempotency_key = request.idempotency_key

        dynamodb = boto3.resource("dynamodb")
        quotes_table = dynamodb.Table(_require_env(QUOTES_TABLE_ENV))
        transaction_log_table = dynamodb.Table(_require_env(UPLOAD_TRANSACTION_LOG_TABLE_ENV))
        payment_ledger_table = dynamodb.Table(_require_env(PAYMENT_LEDGER_TABLE_ENV))

        if idempotency_key:
            idempotency_table = dynamodb.Table(_require_env(UPLOAD_IDEMPOTENCY_TABLE_ENV))
            existing = _fetch_existing_idempotency(
                idempotency_table=idempotency_table,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                now=now,
            )
            if existing:
                existing_status = str(existing.get("status") or "").lower()
                if _is_retryable_upload_after_payment_idempotency(existing):
                    resume_upload_after_payment = True
                    retryable_idempotency_item = existing
                    _log_event(
                        logging.INFO,
                        "idempotency_retryable_upload_resume",
                        idempotency_key=idempotency_key,
                        message="resuming upload after settled payment",
                    )
                elif existing_status == "pending_confirmation":
                    _log_event(
                        logging.INFO,
                        "idempotency_pending_confirmation_cache_hit",
                        idempotency_key=idempotency_key,
                        message="returning refreshed presigned response pending confirmation",
                    )
                    cached_response = _cached_success_response(existing, request=request)
                    _log_api_call_result(
                        event,
                        context,
                        route="/storage/upload",
                        status_code=200,
                        result="success",
                        request=request,
                    )
                    return cached_response
                else:
                    _log_event(
                        logging.INFO,
                        "idempotency_cache_hit",
                        idempotency_key=idempotency_key,
                        message="returning cached response",
                    )
                    cached_response = _cached_success_response(existing, request=request)
                    _log_api_call_result(
                        event,
                        context,
                        route="/storage/upload",
                        status_code=200,
                        result="success",
                        request=request,
                    )
                    return cached_response

        if resume_upload_after_payment and retryable_idempotency_item:
            quote_context = _quote_context_from_retryable_idempotency(retryable_idempotency_item)
            _log_event(
                logging.INFO,
                "quote_context_restored_from_idempotency",
                quote_id=request.quote_id,
                idempotency_key=idempotency_key,
                provider=quote_context.provider,
                location=quote_context.location,
            )
        else:
            quote_resp = quotes_table.get_item(
                Key={"quote_id": request.quote_id},
                ConsistentRead=True,
            )
            quote_context = _build_quote_context(quote_resp.get("Item"), request=request, now=now)
            _log_event(
                logging.INFO,
                "quote_lookup_succeeded",
                quote_id=request.quote_id,
                storage_price=str(quote_context.storage_price),
                storage_price_micro=quote_context.storage_price_micro,
                provider=quote_context.provider,
                location=quote_context.location,
            )

        payment_config = _payment_config()
        requirements = _payment_requirements(quote_context, payment_config)

        if idempotency_key and idempotency_table and not resume_upload_after_payment:
            existing = _claim_idempotency_lock(
                idempotency_table=idempotency_table,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                now=now,
            )
            if existing:
                existing_status = str(existing.get("status") or "").lower()
                if _is_retryable_upload_after_payment_idempotency(existing):
                    resume_upload_after_payment = True
                    retryable_idempotency_item = existing
                    quote_context = _quote_context_from_retryable_idempotency(existing)
                    _log_event(
                        logging.INFO,
                        "idempotency_retryable_upload_resume",
                        idempotency_key=idempotency_key,
                        message="resuming upload after settled payment",
                    )
                elif existing_status == "pending_confirmation":
                    _log_event(
                        logging.INFO,
                        "idempotency_pending_confirmation_cache_hit",
                        idempotency_key=idempotency_key,
                        message="returning refreshed presigned response pending confirmation",
                    )
                    cached_response = _cached_success_response(existing, request=request)
                    _log_api_call_result(
                        event,
                        context,
                        route="/storage/upload",
                        status_code=200,
                        result="success",
                        request=request,
                    )
                    return cached_response
                else:
                    _log_event(
                        logging.INFO,
                        "idempotency_cache_hit",
                        idempotency_key=idempotency_key,
                        message="returning cached response",
                    )
                    cached_response = _cached_success_response(existing, request=request)
                    _log_api_call_result(
                        event,
                        context,
                        route="/storage/upload",
                        status_code=200,
                        result="success",
                        request=request,
                    )
                    return cached_response
            else:
                idempotency_lock_acquired = True
                _log_event(
                    logging.INFO,
                    "idempotency_lock_acquired",
                    idempotency_key=idempotency_key,
                    message="lock acquired",
                )

        payment_ledger_record = _load_confirmed_payment_record(
            payment_ledger_table=payment_ledger_table,
            request=request,
            requirements=requirements,
        )
        payment_result = PaymentVerificationResult(
            trans_id=payment_ledger_record.trans_id,
            network=payment_ledger_record.network,
            asset=payment_ledger_record.asset,
            amount=payment_ledger_record.amount,
        )
        if resume_upload_after_payment and retryable_idempotency_item:
            _log_event(
                logging.INFO,
                "payment_ledger_confirmed_resume_upload",
                trans_id=payment_result.trans_id,
                idempotency_key=idempotency_key,
                message="resuming upload using confirmed payment ledger record",
            )
        else:
            _log_event(
                logging.INFO,
                "payment_ledger_confirmed",
                trans_id=payment_result.trans_id,
                quote_id=request.quote_id,
                wallet_address=request.wallet_address,
                amount=payment_result.amount,
                network=payment_result.network,
            )
        upload_url: str | None = None
        if request.mode == "presigned":
            s3_client = boto3.client("s3", region_name=quote_context.location)
            bucket_name = _bucket_name(request.wallet_address)
            _validate_bucket_name(bucket_name)
            _ensure_bucket_exists(s3_client, bucket_name, quote_context.location)
            upload_url = s3_client.generate_presigned_url(
                "put_object",
                Params=_presigned_put_object_params(
                    bucket_name=bucket_name,
                    object_key=request.object_key,
                    wrapped_dek=request.wrapped_dek,
                    content_length_bytes=request.content_length_bytes,
                ),
                ExpiresIn=PRESIGNED_URL_EXPIRES_IN_SECONDS,
            )
            _log_event(
                logging.INFO,
                "presigned_url_generated",
                bucket_name=bucket_name,
                object_key=request.object_key,
                message="presigned URL generated",
            )
            response_body = {
                "quote_id": request.quote_id,
                "addr": request.wallet_address,
                "addr_hash": _wallet_hash(request.wallet_address),
                "trans_id": payment_result.trans_id,
                "storage_price": float(quote_context.storage_price),
                "object_id": request.object_id,
                "object_key": request.object_key,
                "provider": quote_context.provider,
                "bucket_name": bucket_name,
                "location": quote_context.location,
                "upload_url": upload_url,
                "upload_headers": {
                    "content-type": "application/octet-stream",
                    "x-amz-meta-wrapped-dek": request.wrapped_dek,
                },
                "confirmation_required": True,
            }
            payment_response_header = _encode_json_base64(
                {
                    "trans_id": payment_result.trans_id,
                    "network": payment_result.network,
                    "asset": payment_result.asset,
                    "amount": str(payment_result.amount),
                }
            )
            if (
                idempotency_table
                and idempotency_key
                and request_hash
                and (idempotency_lock_acquired or resume_upload_after_payment)
            ):
                _mark_idempotency_pending_confirmation(
                    idempotency_table=idempotency_table,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    confirm_request_hash=_confirm_request_fingerprint(
                        quote_id=request.quote_id,
                        wallet_address=request.wallet_address,
                        object_key=request.object_key,
                    ),
                    response_body=response_body,
                    payment_response_header=payment_response_header,
                    payment_result=payment_result,
                    quote_context=quote_context,
                    now=now,
                )
                _log_event(
                    logging.DEBUG,
                    "idempotency_marked_pending_confirmation",
                    idempotency_key=idempotency_key,
                )
            _log_api_call_result(
                event,
                context,
                route="/storage/upload",
                status_code=200,
                result="success",
                request=request,
                trans_id=payment_result.trans_id,
            )
            return _response(200, response_body, headers=_payment_response_headers(payment_response_header))
        else:
            if request.ciphertext is None:
                raise BadRequestError("ciphertext is required")
            try:
                bucket_name = _upload_ciphertext_to_s3(
                    wallet_address=request.wallet_address,
                    object_key=request.object_key,
                    ciphertext=request.ciphertext,
                    wrapped_dek=request.wrapped_dek,
                    location=quote_context.location,
                )
            except Exception as s3_exc:
                # Payment was already settled, so preserve the idempotency lock and
                # surface a resumable upload response for operational recovery.
                if idempotency_table and idempotency_key and request_hash:
                    try:
                        _mark_idempotency_upload_retryable(
                            idempotency_table=idempotency_table,
                            idempotency_key=idempotency_key,
                            request_hash=request_hash,
                            payment_result=payment_result,
                            quote_context=quote_context,
                            now=now,
                        )
                    except Exception as idempotency_exc:
                        _log_event(
                            logging.ERROR,
                            "idempotency_mark_retryable_failed",
                            idempotency_key=idempotency_key,
                            quote_id=request.quote_id,
                            trans_id=payment_result.trans_id,
                            error_type=type(idempotency_exc).__name__,
                            error_message=str(idempotency_exc),
                        )
                logger.error(
                    json.dumps(
                        {
                            "event": "s3_upload_failed_after_payment",
                            "quote_id": request.quote_id,
                            "trans_id": payment_result.trans_id,
                            "wallet_address": request.wallet_address,
                            "object_key": request.object_key,
                            "error": str(s3_exc),
                        },
                        default=str,
                    )
                )
                response_body = {
                    "quote_id": request.quote_id,
                    "addr": request.wallet_address,
                    "addr_hash": _wallet_hash(request.wallet_address),
                    "trans_id": payment_result.trans_id,
                    "storage_price": float(quote_context.storage_price),
                    "object_id": request.object_id,
                    "object_key": request.object_key,
                    "provider": quote_context.provider,
                    "bucket_name": _bucket_name(request.wallet_address),
                    "location": quote_context.location,
                    "upload_failed": True,
                    "error": "S3 upload failed after payment settlement. Retry the upload.",
                }
                payment_response_header = _encode_json_base64(
                    {
                        "trans_id": payment_result.trans_id,
                        "network": payment_result.network,
                        "asset": payment_result.asset,
                        "amount": str(payment_result.amount),
                    }
                )
                _log_api_call_result(
                    event,
                    context,
                    route="/storage/upload",
                    status_code=207,
                    result="partial_success",
                    error_code="upload_failed_after_payment",
                    error_message=str(s3_exc),
                    request=request,
                    trans_id=payment_result.trans_id,
                )
                return _response(
                    207,
                    response_body,
                    headers=_payment_response_headers(payment_response_header),
                )
            _log_event(
                logging.INFO,
                "s3_upload_succeeded",
                bucket_name=bucket_name,
                object_key=request.object_key,
                ciphertext_size_bytes=len(request.ciphertext),
            )

        _write_transaction_log(
            transaction_log_table=transaction_log_table,
            now=now,
            request=request,
            quote_context=quote_context,
            payment_result=payment_result,
            recipient_wallet=payment_ledger_record.recipient_wallet or payment_config["recipient_wallet"],
            trans_id=payment_result.trans_id,
            bucket_name=bucket_name,
        )
        _log_event(
            logging.INFO,
            "transaction_log_written",
            trans_id=payment_result.trans_id,
            quote_id=request.quote_id,
        )

        try:
            quotes_table.delete_item(Key={"quote_id": request.quote_id})
            _log_event(
                logging.DEBUG,
                "consumed_quote_deleted",
                quote_id=request.quote_id,
                message="consumed quote deleted",
            )
        except ClientError:
            pass

        response_body = {
            "quote_id": request.quote_id,
            "addr": request.wallet_address,
            "addr_hash": _wallet_hash(request.wallet_address),
            "trans_id": payment_result.trans_id,
            "storage_price": float(quote_context.storage_price),
            "object_id": request.object_id,
            "object_key": request.object_key,
            "provider": quote_context.provider,
            "bucket_name": bucket_name,
            "location": quote_context.location,
        }
        payment_response_header = _encode_json_base64(
            {
                "trans_id": payment_result.trans_id,
                "network": payment_result.network,
                "asset": payment_result.asset,
                "amount": str(payment_result.amount),
            }
        )

        if (
            idempotency_table
            and idempotency_key
            and request_hash
            and (idempotency_lock_acquired or resume_upload_after_payment)
        ):
            _mark_idempotency_completed(
                idempotency_table=idempotency_table,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_body=response_body,
                payment_response_header=payment_response_header,
                now=now,
            )
            _log_event(
                logging.DEBUG,
                "idempotency_marked_completed",
                idempotency_key=idempotency_key,
            )

        _log_api_call_result(
            event,
            context,
            route="/storage/upload",
            status_code=200,
            result="success",
            request=request,
            trans_id=payment_result.trans_id,
        )
        return _response(200, response_body, headers=_payment_response_headers(payment_response_header))

    except ForbiddenError as exc:
        _log_event(
            logging.WARNING,
            "upload_request_forbidden",
            error_type=type(exc).__name__,
            error_message=str(exc),
            quote_id=request.quote_id if request else None,
            wallet_address=request.wallet_address if request else None,
        )
        if idempotency_lock_acquired and idempotency_table and idempotency_key:
            _release_idempotency_lock(idempotency_table, idempotency_key)
        _log_api_call_result(
            event,
            context,
            route="/storage/upload",
            status_code=403,
            result="forbidden",
            error_code="wallet_mismatch",
            error_message=str(exc),
            request=request,
        )
        return _error_response(403, "forbidden", str(exc))

    except BadRequestError as exc:
        _log_event(
            logging.WARNING,
            "upload_request_bad_request",
            error_type=type(exc).__name__,
            error_message=str(exc),
            quote_id=request.quote_id if request else None,
            wallet_address=request.wallet_address if request else None,
        )
        if idempotency_lock_acquired and idempotency_table and idempotency_key:
            _release_idempotency_lock(idempotency_table, idempotency_key)
        _log_api_call_result(
            event,
            context,
            route="/storage/upload",
            status_code=400,
            result="bad_request",
            error_code="bad_request",
            error_message=str(exc),
            request=request,
        )
        return _error_response(400, "Bad request", str(exc))

    except NotFoundError as exc:
        _log_event(
            logging.WARNING,
            "upload_quote_not_found",
            error_type=type(exc).__name__,
            error_message=str(exc),
            quote_id=request.quote_id if request else None,
            wallet_address=request.wallet_address if request else None,
        )
        if idempotency_lock_acquired and idempotency_table and idempotency_key:
            _release_idempotency_lock(idempotency_table, idempotency_key)
        _log_api_call_result(
            event,
            context,
            route="/storage/upload",
            status_code=404,
            result="not_found",
            error_code="quote_not_found",
            error_message=str(exc),
            request=request,
        )
        return _error_response(404, "quote_not_found", "Quote not found or expired")

    except PaymentRequiredError as exc:
        _log_event(
            logging.WARNING,
            "upload_payment_required",
            error_type=type(exc).__name__,
            error_message=exc.message,
            quote_id=request.quote_id if request else None,
            wallet_address=request.wallet_address if request else None,
        )
        if idempotency_lock_acquired and idempotency_table and idempotency_key:
            _release_idempotency_lock(idempotency_table, idempotency_key)
        headers = _payment_required_headers(exc.requirements)
        _log_api_call_result(
            event,
            context,
            route="/storage/upload",
            status_code=402,
            result="payment_required",
            error_code="payment_required",
            error_message=exc.message,
            request=request,
        )
        return _error_response(402, "payment_required", exc.message, details=exc.details, headers=headers)

    except ConflictError as exc:
        _log_event(
            logging.WARNING,
            "upload_idempotency_conflict",
            error_type=type(exc).__name__,
            error_message=str(exc),
            quote_id=request.quote_id if request else None,
            wallet_address=request.wallet_address if request else None,
        )
        _log_api_call_result(
            event,
            context,
            route="/storage/upload",
            status_code=409,
            result="conflict",
            error_code="idempotency_conflict",
            error_message=str(exc),
            request=request,
        )
        return _error_response(409, "conflict", str(exc))

    except Exception as exc:
        _log_event(
            logging.ERROR,
            "upload_internal_error",
            error_type=type(exc).__name__,
            error_message=str(exc),
            quote_id=request.quote_id if request else None,
            wallet_address=request.wallet_address if request else None,
        )
        if idempotency_lock_acquired and idempotency_table and idempotency_key:
            _release_idempotency_lock(idempotency_table, idempotency_key)
        _log_api_call_result(
            event,
            context,
            route="/storage/upload",
            status_code=500,
            result="internal_error",
            error_code="internal_error",
            error_message=str(exc),
            request=request,
        )
        return _error_response(500, "Internal error", str(exc))


def confirm_upload_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    request: ParsedUploadConfirmRequest | None = None

    try:
        now = int(time.time())
        request = parse_confirm_input(event)
        _log_event(
            logging.INFO,
            "confirm_request_parsed",
            request_id=_request_id(event, context),
            method=_request_method(event),
            path=_request_path(event, "/storage/upload/confirm"),
            quote_id=request.quote_id,
            wallet_address=request.wallet_address,
            object_key=request.object_key,
            idempotency_key=request.idempotency_key,
        )
        _require_authorized_wallet(event, request.wallet_address)

        dynamodb = boto3.resource("dynamodb")
        quotes_table = dynamodb.Table(_require_env(QUOTES_TABLE_ENV))
        transaction_log_table = dynamodb.Table(_require_env(UPLOAD_TRANSACTION_LOG_TABLE_ENV))
        idempotency_table = dynamodb.Table(_require_env(UPLOAD_IDEMPOTENCY_TABLE_ENV))

        idempotency_response = idempotency_table.get_item(
            Key={"idempotency_key": request.idempotency_key},
            ConsistentRead=True,
        )
        idempotency_item = idempotency_response.get("Item")
        if not idempotency_item:
            _log_api_call_result(
                event,
                context,
                route="/storage/upload/confirm",
                status_code=404,
                result="not_found",
                error_code="idempotency_not_found",
                error_message="Upload confirmation idempotency record not found",
                request=request,
            )
            return _error_response(404, "not_found", "Upload confirmation idempotency record not found")

        try:
            expires_at = int(idempotency_item.get("expires_at"))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Stored pending confirmation expires_at is invalid") from exc
        if expires_at <= now:
            try:
                idempotency_table.delete_item(
                    Key={"idempotency_key": request.idempotency_key},
                    ConditionExpression="expires_at <= :now",
                    ExpressionAttributeValues={":now": now},
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                    raise
            _log_api_call_result(
                event,
                context,
                route="/storage/upload/confirm",
                status_code=404,
                result="not_found",
                error_code="idempotency_not_found",
                error_message="Upload confirmation idempotency record not found",
                request=request,
            )
            return _error_response(404, "not_found", "Upload confirmation idempotency record not found")

        status = str(idempotency_item.get("status") or "").lower()
        if status not in {"completed", "pending_confirmation"}:
            _log_api_call_result(
                event,
                context,
                route="/storage/upload/confirm",
                status_code=409,
                result="conflict",
                error_code="confirm_not_pending",
                error_message="Upload confirmation is not pending for this Idempotency-Key",
                request=request,
            )
            return _error_response(409, "conflict", "Upload confirmation is not pending for this Idempotency-Key")

        confirm_hash = _confirm_request_fingerprint(
            quote_id=request.quote_id,
            wallet_address=request.wallet_address,
            object_key=request.object_key,
        )
        stored_confirm_hash = str(idempotency_item.get("confirm_request_hash") or "").strip()
        if stored_confirm_hash and stored_confirm_hash != confirm_hash:
            raise ConflictError("Idempotency-Key cannot be reused with a different confirmation payload")

        response_body_raw = idempotency_item.get("response_body")
        if not isinstance(response_body_raw, str):
            raise RuntimeError("Stored pending confirmation response_body is invalid")
        pending_response_body = json.loads(response_body_raw)
        if not isinstance(pending_response_body, dict):
            raise RuntimeError("Stored pending confirmation response_body is invalid")

        if str(pending_response_body.get("quote_id") or "").strip() != request.quote_id:
            raise ConflictError("quote_id does not match pending confirmation idempotency state")
        if str(pending_response_body.get("object_key") or "").strip() != request.object_key:
            raise ConflictError("object_key does not match pending confirmation idempotency state")
        if str(pending_response_body.get("addr") or "").strip() != request.wallet_address:
            raise ConflictError("wallet_address does not match pending confirmation idempotency state")

        if status == "completed":
            cached_response = _cached_success_response(idempotency_item)
            _log_api_call_result(
                event,
                context,
                route="/storage/upload/confirm",
                status_code=200,
                result="success",
                request=request,
            )
            return cached_response

        payment_result = _payment_result_from_retryable_idempotency(idempotency_item)
        quote_context = _quote_context_from_retryable_idempotency(idempotency_item)

        bucket_name = _bucket_name(request.wallet_address)
        s3_client = boto3.client("s3", region_name=quote_context.location)
        try:
            s3_client.head_object(Bucket=bucket_name, Key=request.object_key)
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")
            if error_code in {"404", "NotFound", "NoSuchKey", "NoSuchBucket"}:
                _log_api_call_result(
                    event,
                    context,
                    route="/storage/upload/confirm",
                    status_code=404,
                    result="not_found",
                    error_code="object_not_found",
                    error_message="S3 object not found. Upload the file using the presigned URL first.",
                    request=request,
                )
                return _error_response(
                    404,
                    "not_found",
                    "S3 object not found. Upload the file using the presigned URL first.",
                )
            raise

        _log_event(
            logging.INFO,
            "confirm_s3_object_verified",
            quote_id=request.quote_id,
            wallet_address=request.wallet_address,
            object_key=request.object_key,
            bucket_name=bucket_name,
        )

        payment_config = _payment_config()
        object_id = str(pending_response_body.get("object_id") or request.object_key).strip() or request.object_key
        request_for_log = ParsedUploadRequest(
            quote_id=request.quote_id,
            wallet_address=request.wallet_address,
            object_id=object_id,
            object_id_hash="",
            object_key=request.object_key,
            provider=quote_context.provider,
            location=quote_context.location,
            mode="presigned",
            content_sha256=None,
            ciphertext=None,
            wrapped_dek="",
            idempotency_key=request.idempotency_key,
            content_length_bytes=None,
        )
        _write_transaction_log(
            transaction_log_table=transaction_log_table,
            now=now,
            request=request_for_log,
            quote_context=quote_context,
            payment_result=payment_result,
            recipient_wallet=payment_config["recipient_wallet"],
            trans_id=payment_result.trans_id,
            bucket_name=bucket_name,
        )
        _log_event(
            logging.INFO,
            "confirm_transaction_log_written",
            quote_id=request.quote_id,
            trans_id=payment_result.trans_id,
            idempotency_key=request.idempotency_key,
        )

        try:
            quotes_table.delete_item(Key={"quote_id": request.quote_id})
        except ClientError:
            pass

        completed_response_body = dict(pending_response_body)
        completed_response_body.pop("upload_url", None)
        completed_response_body.pop("upload_headers", None)
        completed_response_body.pop("confirmation_required", None)

        payment_response_header = str(idempotency_item.get("payment_response") or "").strip()
        if not payment_response_header:
            payment_response_header = _encode_json_base64(
                {
                    "trans_id": payment_result.trans_id,
                    "network": payment_result.network,
                    "asset": payment_result.asset,
                    "amount": str(payment_result.amount),
                }
            )

        stored_request_hash = str(idempotency_item.get("request_hash") or "").strip()
        if not stored_request_hash:
            raise RuntimeError("Stored pending confirmation request_hash is missing")

        _mark_idempotency_completed(
            idempotency_table=idempotency_table,
            idempotency_key=request.idempotency_key,
            request_hash=stored_request_hash,
            response_body=completed_response_body,
            payment_response_header=payment_response_header,
            now=now,
        )
        _log_event(
            logging.INFO,
            "confirm_completed",
            quote_id=request.quote_id,
            trans_id=payment_result.trans_id,
            idempotency_key=request.idempotency_key,
        )

        _log_api_call_result(
            event,
            context,
            route="/storage/upload/confirm",
            status_code=200,
            result="success",
            request=request,
            trans_id=payment_result.trans_id,
        )
        return _response(
            200,
            completed_response_body,
            headers=_payment_response_headers(payment_response_header),
        )

    except ForbiddenError as exc:
        _log_api_call_result(
            event,
            context,
            route="/storage/upload/confirm",
            status_code=403,
            result="forbidden",
            error_code="wallet_mismatch",
            error_message=str(exc),
            request=request,
        )
        return _error_response(403, "forbidden", str(exc))
    except BadRequestError as exc:
        _log_api_call_result(
            event,
            context,
            route="/storage/upload/confirm",
            status_code=400,
            result="bad_request",
            error_code="bad_request",
            error_message=str(exc),
            request=request,
        )
        return _error_response(400, "Bad request", str(exc))
    except ConflictError as exc:
        _log_api_call_result(
            event,
            context,
            route="/storage/upload/confirm",
            status_code=409,
            result="conflict",
            error_code="idempotency_conflict",
            error_message=str(exc),
            request=request,
        )
        return _error_response(409, "conflict", str(exc))
    except Exception as exc:
        _log_event(
            logging.ERROR,
            "confirm_internal_error",
            error_type=type(exc).__name__,
            error_message=str(exc),
            quote_id=request.quote_id if request else None,
            wallet_address=request.wallet_address if request else None,
            idempotency_key=request.idempotency_key if request else None,
        )
        _log_api_call_result(
            event,
            context,
            route="/storage/upload/confirm",
            status_code=500,
            result="internal_error",
            error_code="internal_error",
            error_message=str(exc),
            request=request,
        )
        return _error_response(500, "Internal error", str(exc))
