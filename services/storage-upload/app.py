"""
Lambda handler for POST /storage/upload.

Flow:
1. Parse request and optional Idempotency-Key.
2. Lookup and validate quote in DynamoDB.
3. Verify payment authorization (EIP-712 TransferWithAuthorization).
4. Settle payment (mock tx id by default; optional on-chain mode).
5. Upload ciphertext to wallet-scoped S3 bucket with wrapped DEK metadata.
6. Write upload transaction log row in DynamoDB.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any

import boto3
from botocore.exceptions import ClientError

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

QUOTES_TABLE_ENV = "QUOTES_TABLE_NAME"
UPLOAD_TRANSACTION_LOG_TABLE_ENV = "UPLOAD_TRANSACTION_LOG_TABLE_NAME"
UPLOAD_IDEMPOTENCY_TABLE_ENV = "UPLOAD_IDEMPOTENCY_TABLE_NAME"

PAYMENT_SIGNATURE_HEADER_NAMES = (
    "PAYMENT-SIGNATURE",
    "payment-signature",
    "X-PAYMENT",
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
    ciphertext: bytes
    wrapped_dek: str
    idempotency_key: str | None
    payment_header: str | None


@dataclass(frozen=True)
class QuoteContext:
    quote_id: str
    wallet_address: str
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
        if error_code not in {"404", "NotFound", "NoSuchBucket"}:
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
    payment_header: str | None = None
    for header_name in PAYMENT_SIGNATURE_HEADER_NAMES:
        header_value = _header_value(headers, header_name)
        if header_value:
            payment_header = header_value
            break

    return ParsedUploadRequest(
        quote_id=quote_id,
        wallet_address=wallet_address,
        object_id=object_id,
        object_id_hash=object_id_hash,
        object_key=object_key,
        provider=provider,
        location=location,
        ciphertext=ciphertext,
        wrapped_dek=wrapped_dek,
        idempotency_key=idempotency_key,
        payment_header=payment_header,
    )


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return value


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
    location = str(quote_item.get("location") or quote_item.get("region") or request.location).strip() or request.location
    wallet_address = quote_addr or request.wallet_address
    storage_price_micro = int(
        (storage_price * USDC_DECIMALS).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )

    return QuoteContext(
        quote_id=request.quote_id,
        wallet_address=wallet_address,
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
    return {
        "scheme": "exact",
        "network": payment_config["payment_network"],
        "asset": payment_config["payment_asset"],
        "payTo": payment_config["recipient_wallet"],
        "amount": str(quote_context.storage_price_micro),
    }


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


def _onchain_settle_payment(authorization: TransferAuthorization) -> str:
    try:
        from eth_account import Account
        from web3 import Web3
    except ImportError as exc:  # pragma: no cover - runtime dependency guard
        raise RuntimeError("web3 and eth-account dependencies are required for on-chain settlement") from exc

    rpc_url = os.environ.get("MNEMOSPARK_BASE_RPC_URL", "").strip()
    relayer_private_key = os.environ.get("MNEMOSPARK_RELAYER_PRIVATE_KEY", "").strip()
    if not rpc_url:
        raise RuntimeError("MNEMOSPARK_BASE_RPC_URL is required for on-chain settlement mode")
    if not relayer_private_key:
        raise RuntimeError("MNEMOSPARK_RELAYER_PRIVATE_KEY is required for on-chain settlement mode")

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

    settlement_mode = os.environ.get("MNEMOSPARK_PAYMENT_SETTLEMENT_MODE", "mock").strip().lower() or "mock"
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
    stable_payload = {
        "quote_id": request.quote_id,
        "wallet_address": request.wallet_address,
        "object_id": request.object_id,
        "object_id_hash": request.object_id_hash,
        "object_key": request.object_key,
        "provider": request.provider,
        "location": request.location,
        "wrapped_dek": request.wrapped_dek,
        "ciphertext_sha256": hashlib.sha256(request.ciphertext).hexdigest(),
    }
    encoded = json.dumps(stable_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _fetch_existing_idempotency(
    idempotency_table: Any,
    idempotency_key: str,
    request_hash: str,
    now: int,
) -> dict[str, Any] | None:
    response = idempotency_table.get_item(
        Key={"idempotency_key": idempotency_key},
        ConsistentRead=True,
    )
    item = response.get("Item")
    if not item:
        return None

    expires_at = _coerce_int(item.get("expires_at"), "idempotency.expires_at")
    if expires_at <= now:
        idempotency_table.delete_item(Key={"idempotency_key": idempotency_key})
        return None

    stored_hash = str(item.get("request_hash") or "")
    if stored_hash and stored_hash != request_hash:
        raise ConflictError("Idempotency-Key cannot be reused with a different request payload")

    status = str(item.get("status") or "").lower()
    if status == "completed":
        return item
    if status == "in_progress":
        raise ConflictError("Upload is already in progress for this Idempotency-Key")

    raise ConflictError("Idempotency-Key is in an unknown state")


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


def _release_idempotency_lock(idempotency_table: Any, idempotency_key: str) -> None:
    try:
        idempotency_table.delete_item(Key={"idempotency_key": idempotency_key})
    except Exception:
        # Best-effort release; lock naturally expires via TTL if delete fails.
        return


def _cached_success_response(idempotency_item: dict[str, Any]) -> dict[str, Any]:
    response_body_raw = idempotency_item.get("response_body")
    if not isinstance(response_body_raw, str):
        raise RuntimeError("Stored idempotency response_body is invalid")
    response_body = json.loads(response_body_raw)
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
    trans_id: str,
    bucket_name: str,
) -> None:
    timestamp = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    transaction_log_table.put_item(
        Item={
            "quote_id": request.quote_id,
            "trans_id": trans_id,
            "timestamp": timestamp,
            "addr": request.wallet_address,
            "addr_hash": _wallet_hash(request.wallet_address),
            "storage_price": quote_context.storage_price,
            "object_id": request.object_id,
            "object_key": request.object_key,
            "provider": quote_context.provider,
            "bucket_name": bucket_name,
            "location": quote_context.location,
            "idempotency_key": request.idempotency_key or "",
        }
    )


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    idempotency_lock_acquired = False
    idempotency_table: Any | None = None
    idempotency_key: str | None = None
    request_hash: str | None = None

    try:
        now = int(time.time())
        request = parse_input(event)
        request_hash = _request_fingerprint(request)
        idempotency_key = request.idempotency_key

        dynamodb = boto3.resource("dynamodb")
        quotes_table = dynamodb.Table(_require_env(QUOTES_TABLE_ENV))
        transaction_log_table = dynamodb.Table(_require_env(UPLOAD_TRANSACTION_LOG_TABLE_ENV))

        if idempotency_key:
            idempotency_table = dynamodb.Table(_require_env(UPLOAD_IDEMPOTENCY_TABLE_ENV))
            existing = _fetch_existing_idempotency(
                idempotency_table=idempotency_table,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                now=now,
            )
            if existing:
                return _cached_success_response(existing)

        quote_resp = quotes_table.get_item(
            Key={"quote_id": request.quote_id},
            ConsistentRead=True,
        )
        quote_context = _build_quote_context(quote_resp.get("Item"), request=request, now=now)

        payment_config = _payment_config()
        requirements = _payment_requirements(quote_context, payment_config)

        if idempotency_key and idempotency_table:
            existing = _claim_idempotency_lock(
                idempotency_table=idempotency_table,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                now=now,
            )
            if existing:
                return _cached_success_response(existing)
            idempotency_lock_acquired = True

        payment_result = verify_and_settle_payment(
            payment_header=request.payment_header,
            wallet_address=request.wallet_address,
            quote_id=request.quote_id,
            expected_amount=quote_context.storage_price_micro,
            expected_recipient=payment_config["recipient_wallet"],
            expected_network=payment_config["payment_network"],
            expected_asset=payment_config["payment_asset"],
            requirements=requirements,
        )

        bucket_name = _upload_ciphertext_to_s3(
            wallet_address=request.wallet_address,
            object_key=request.object_key,
            ciphertext=request.ciphertext,
            wrapped_dek=request.wrapped_dek,
            location=quote_context.location,
        )

        _write_transaction_log(
            transaction_log_table=transaction_log_table,
            now=now,
            request=request,
            quote_context=quote_context,
            trans_id=payment_result.trans_id,
            bucket_name=bucket_name,
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
        }
        payment_response_header = _encode_json_base64(
            {
                "trans_id": payment_result.trans_id,
                "network": payment_result.network,
                "asset": payment_result.asset,
                "amount": str(payment_result.amount),
            }
        )

        if idempotency_lock_acquired and idempotency_table and idempotency_key and request_hash:
            _mark_idempotency_completed(
                idempotency_table=idempotency_table,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                response_body=response_body,
                payment_response_header=payment_response_header,
                now=now,
            )

        return _response(200, response_body, headers=_payment_response_headers(payment_response_header))

    except BadRequestError as exc:
        if idempotency_lock_acquired and idempotency_table and idempotency_key:
            _release_idempotency_lock(idempotency_table, idempotency_key)
        return _error_response(400, "Bad request", str(exc))

    except NotFoundError:
        if idempotency_lock_acquired and idempotency_table and idempotency_key:
            _release_idempotency_lock(idempotency_table, idempotency_key)
        return _error_response(404, "quote_not_found", "Quote not found or expired")

    except PaymentRequiredError as exc:
        if idempotency_lock_acquired and idempotency_table and idempotency_key:
            _release_idempotency_lock(idempotency_table, idempotency_key)
        headers = _payment_required_headers(exc.requirements)
        return _error_response(402, "payment_required", exc.message, details=exc.details, headers=headers)

    except ConflictError as exc:
        return _error_response(409, "conflict", str(exc))

    except Exception as exc:
        if idempotency_lock_acquired and idempotency_table and idempotency_key:
            _release_idempotency_lock(idempotency_table, idempotency_key)
        return _error_response(500, "Internal error", str(exc))
