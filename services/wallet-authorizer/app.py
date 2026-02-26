"""
Lambda authorizer for wallet-proof authentication.

Supported flow:
- Reads `X-Wallet-Signature` (or legacy lowercase header) from request authorizer events.
- Reads `authorizationToken` from token authorizer events.
- Validates wallet proof payload format and EIP-712 signature.
- Enforces route-specific behavior:
  * POST /price-storage: wallet proof optional.
  * Storage routes: wallet proof required + signer must match request wallet_address.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

MNEMOSPARK_REQUEST_TYPES = {
    "MnemosparkRequest": [
        {"name": "method", "type": "string"},
        {"name": "path", "type": "string"},
        {"name": "walletAddress", "type": "address"},
        {"name": "nonce", "type": "bytes32"},
        {"name": "timestamp", "type": "uint256"},
    ]
}

DOMAIN_NAME = "Mnemospark"
DOMAIN_VERSION = "1"
DEFAULT_VERIFYING_CONTRACT = "0x0000000000000000000000000000000000000001"
ALLOWED_CHAIN_IDS = (8453, 84532)

ADDRESS_PATTERN = re.compile(r"^0x[a-fA-F0-9]{40}$")
NONCE_PATTERN = re.compile(r"^0x[a-fA-F0-9]{64}$")
SIGNATURE_PATTERN = re.compile(r"^0x[a-fA-F0-9]{130}$")

PRICE_STORAGE_ROUTE = ("POST", "/price-storage")
STORAGE_ROUTE_METHODS: dict[str, set[str]] = {
    "/storage/upload": {"POST"},
    "/storage/ls": {"GET", "POST"},
    "/storage/download": {"GET", "POST"},
    "/storage/delete": {"POST", "DELETE"},
}


class AuthError(ValueError):
    """Raised when request authorization cannot be validated."""


@dataclass(frozen=True)
class WalletProof:
    method: str
    path: str
    wallet_address: str
    nonce: str
    timestamp: int
    declared_address: str
    signature: str


def _max_signature_age_seconds() -> int:
    raw = str(os.environ.get("MNEMOSPARK_AUTH_MAX_AGE_SECONDS", "300")).strip()
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return 300
    return parsed if parsed > 0 else 300


MAX_SIGNATURE_AGE_SECONDS = _max_signature_age_seconds()
MAX_SIGNATURE_FUTURE_SKEW_SECONDS = 60
VERIFYING_CONTRACT = (os.environ.get("MNEMOSPARK_REQUEST_VERIFYING_CONTRACT") or "").strip() or DEFAULT_VERIFYING_CONTRACT


def _safe_str(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _normalize_address(value: Any, field_name: str) -> str:
    normalized = _safe_str(value)
    if not ADDRESS_PATTERN.fullmatch(normalized):
        raise AuthError(f"{field_name} must be a valid hex wallet address")
    return normalized.lower()


def _normalize_signature(value: Any) -> str:
    signature = _safe_str(value)
    if not signature:
        raise AuthError("signature is required")
    if not signature.startswith("0x"):
        signature = f"0x{signature}"
    if not SIGNATURE_PATTERN.fullmatch(signature):
        raise AuthError("signature must be a 65-byte hex string")
    return signature


def _normalize_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        if isinstance(key, str) and value is not None:
            normalized[key.lower()] = str(value).strip()
    return normalized


def _decode_base64_to_text(value: str, field_name: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuthError(f"{field_name} must be base64-encoded") from exc
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthError(f"{field_name} must be valid UTF-8 after base64 decode") from exc


def _parse_json_object(raw_json: str, field_name: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise AuthError(f"{field_name} must contain valid JSON") from exc
    if not isinstance(parsed, dict):
        raise AuthError(f"{field_name} JSON must be an object")
    return parsed


def _normalize_path(path: str, stage: str | None) -> str:
    normalized = _safe_str(path)
    if not normalized:
        raise AuthError("request path is required")

    normalized = normalized.split("?", 1)[0]
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"

    if stage:
        prefix = f"/{stage}"
        if normalized == prefix:
            normalized = "/"
        elif normalized.startswith(f"{prefix}/"):
            normalized = normalized[len(prefix) :]

    if len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized.rstrip("/")

    return normalized or "/"


def _resource_arn(event: dict[str, Any]) -> str:
    for key in ("methodArn", "routeArn"):
        value = _safe_str(event.get(key))
        if value:
            return value
    return "*"


def _event_stage(event: dict[str, Any]) -> str | None:
    request_context = event.get("requestContext")
    if not isinstance(request_context, dict):
        return None
    stage = _safe_str(request_context.get("stage"))
    return stage or None


def _method_path_from_method_arn(method_arn: str) -> tuple[str, str]:
    if not method_arn:
        raise AuthError("methodArn is required for token authorizer events")

    arn_parts = method_arn.split(":")
    if len(arn_parts) < 6:
        raise AuthError("methodArn has an unexpected format")

    resource_part = arn_parts[5]
    segments = resource_part.split("/")
    if len(segments) < 3:
        raise AuthError("methodArn is missing method/path segments")

    method = _safe_str(segments[2]).upper()
    path = "/" + "/".join(segment for segment in segments[3:] if segment)
    if not path.strip("/"):
        path = "/"
    return method, _normalize_path(path, stage=None)


def _resolve_method_and_path(event: dict[str, Any]) -> tuple[str, str]:
    event_type = _safe_str(event.get("type")).upper()
    if event_type == "TOKEN":
        return _method_path_from_method_arn(_resource_arn(event))

    route_key = _safe_str(event.get("routeKey"))
    if route_key and route_key != "$default" and " " in route_key:
        method, route_path = route_key.split(" ", 1)
        return method.strip().upper(), _normalize_path(route_path, stage=_event_stage(event))

    request_context = event.get("requestContext")
    if not isinstance(request_context, dict):
        request_context = {}

    method = _safe_str(event.get("httpMethod")) or _safe_str(request_context.get("httpMethod"))
    if not method:
        http_context = request_context.get("http")
        if isinstance(http_context, dict):
            method = _safe_str(http_context.get("method"))

    path = (
        _safe_str(event.get("resource"))
        or _safe_str(event.get("path"))
        or _safe_str(event.get("rawPath"))
        or _safe_str(request_context.get("resourcePath"))
        or _safe_str(request_context.get("path"))
    )

    if not method:
        method, path_from_arn = _method_path_from_method_arn(_resource_arn(event))
        return method, path_from_arn

    if not path:
        raise AuthError("unable to determine request path")

    return method.upper(), _normalize_path(path, stage=_event_stage(event))


def _decode_event_body(event: dict[str, Any]) -> dict[str, Any]:
    body = event.get("body")
    if body in (None, ""):
        return {}

    if isinstance(body, dict):
        return body

    if not isinstance(body, str):
        raise AuthError("request body must be a JSON object when provided")

    raw_body = body
    if event.get("isBase64Encoded"):
        raw_body = _decode_base64_to_text(raw_body, "body")

    return _parse_json_object(raw_body, "body")


def _collect_request_params(event: dict[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = {}

    query_params = event.get("queryStringParameters")
    if query_params is not None:
        if not isinstance(query_params, dict):
            raise AuthError("queryStringParameters must be an object when provided")
        for key, value in query_params.items():
            if value is not None:
                params[key] = value

    params.update(_decode_event_body(event))
    return params


def _extract_request_wallet(event: dict[str, Any]) -> str | None:
    params = _collect_request_params(event)
    wallets: list[str] = []
    for field_name in ("wallet_address", "walletAddress"):
        if field_name in params and params[field_name] not in (None, ""):
            wallets.append(_normalize_address(params[field_name], field_name))

    if not wallets:
        return None

    first = wallets[0]
    for candidate in wallets[1:]:
        if candidate != first:
            raise AuthError("wallet_address values in request do not match")
    return first


def _extract_wallet_header(event: dict[str, Any]) -> str | None:
    token_value = _safe_str(event.get("authorizationToken"))
    if token_value:
        return token_value

    headers = _normalize_headers(event.get("headers"))
    header_value = _safe_str(headers.get("x-wallet-signature"))
    return header_value or None


def _classify_route(method: str, path: str) -> str:
    if (method, path) == PRICE_STORAGE_ROUTE:
        return "price_optional"

    allowed_methods = STORAGE_ROUTE_METHODS.get(path)
    if allowed_methods and method in allowed_methods:
        return "storage_required"

    return "unsupported"


def _parse_wallet_proof(header_value: str) -> WalletProof:
    proof_json = _decode_base64_to_text(header_value, "X-Wallet-Signature")
    envelope = _parse_json_object(proof_json, "X-Wallet-Signature")

    payload_b64 = _safe_str(envelope.get("payloadB64"))
    if not payload_b64:
        raise AuthError("payloadB64 is required")

    signature = _normalize_signature(envelope.get("signature"))
    declared_address = _normalize_address(envelope.get("address"), "address")

    payload_raw = _decode_base64_to_text(payload_b64, "payloadB64")
    payload = _parse_json_object(payload_raw, "payloadB64")

    method = _safe_str(payload.get("method"))
    path = _safe_str(payload.get("path"))
    wallet_address = _normalize_address(payload.get("walletAddress"), "walletAddress")
    nonce = _safe_str(payload.get("nonce"))
    timestamp_raw = payload.get("timestamp")

    if not method:
        raise AuthError("payload method is required")
    if not path:
        raise AuthError("payload path is required")
    if "?" in path:
        raise AuthError("payload path must not include query string")
    if not NONCE_PATTERN.fullmatch(nonce):
        raise AuthError("nonce must be a 32-byte hex string")

    try:
        timestamp = int(str(timestamp_raw).strip())
    except (TypeError, ValueError) as exc:
        raise AuthError("timestamp must be an integer Unix timestamp in seconds") from exc
    if timestamp <= 0:
        raise AuthError("timestamp must be a positive Unix timestamp")

    return WalletProof(
        method=method,
        path=_normalize_path(path, stage=None),
        wallet_address=wallet_address,
        nonce=nonce,
        timestamp=timestamp,
        declared_address=declared_address,
        signature=signature,
    )


def _recover_signer(proof: WalletProof) -> str:
    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data
    except ImportError as exc:  # pragma: no cover - runtime dependency guard
        raise RuntimeError("eth-account dependency is required for EIP-712 verification") from exc

    message = {
        "method": proof.method,
        "path": proof.path,
        "walletAddress": proof.wallet_address,
        "nonce": proof.nonce,
        "timestamp": int(proof.timestamp),
    }
    domain = {
        "name": DOMAIN_NAME,
        "version": DOMAIN_VERSION,
        "verifyingContract": VERIFYING_CONTRACT,
    }

    for chain_id in ALLOWED_CHAIN_IDS:
        signable = encode_typed_data(
            domain_data={**domain, "chainId": chain_id},
            message_types=MNEMOSPARK_REQUEST_TYPES,
            message_data=message,
        )
        try:
            recovered = _normalize_address(Account.recover_message(signable, signature=proof.signature), "recovered signer")
        except Exception:
            continue
        if recovered == proof.declared_address:
            return recovered

    raise AuthError("EIP-712 signature verification failed")


def _verify_wallet_proof(header_value: str, method: str, path: str) -> str:
    proof = _parse_wallet_proof(header_value)

    if proof.method.upper() != method:
        raise AuthError("signed method does not match request method")
    if proof.path != path:
        raise AuthError("signed path does not match request path")

    now = int(time.time())
    if proof.timestamp < now - MAX_SIGNATURE_AGE_SECONDS:
        raise AuthError("wallet signature has expired")
    if proof.timestamp > now + MAX_SIGNATURE_FUTURE_SKEW_SECONDS:
        raise AuthError("wallet signature timestamp is too far in the future")

    signer = _recover_signer(proof)
    if signer != proof.declared_address:
        raise AuthError("signature signer does not match declared address")
    if signer != proof.wallet_address:
        raise AuthError("signature signer does not match payload walletAddress")

    return signer


def _build_policy(effect: str, resource_arn: str, principal_id: str, wallet_address: str | None = None) -> dict[str, Any]:
    response: dict[str, Any] = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource_arn or "*",
                }
            ],
        },
    }
    if wallet_address:
        response["context"] = {"walletAddress": wallet_address}
    return response


def _allow(resource_arn: str, wallet_address: str | None = None) -> dict[str, Any]:
    principal_id = wallet_address or "anonymous"
    return _build_policy("Allow", resource_arn, principal_id=principal_id, wallet_address=wallet_address)


def _deny(resource_arn: str) -> dict[str, Any]:
    return _build_policy("Deny", resource_arn, principal_id="unauthorized")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    resource_arn = _resource_arn(event)

    try:
        method, path = _resolve_method_and_path(event)
        route_mode = _classify_route(method, path)
        if route_mode == "unsupported":
            return _deny(resource_arn)

        wallet_header = _extract_wallet_header(event)
        if route_mode == "price_optional" and wallet_header is None:
            return _allow(resource_arn, wallet_address=None)
        if wallet_header is None:
            return _deny(resource_arn)

        signer_wallet = _verify_wallet_proof(wallet_header, method=method, path=path)
        request_wallet = _extract_request_wallet(event)

        if route_mode == "storage_required":
            if request_wallet is None:
                return _deny(resource_arn)
            if request_wallet != signer_wallet:
                return _deny(resource_arn)
        elif request_wallet is not None and request_wallet != signer_wallet:
            return _deny(resource_arn)

        return _allow(resource_arn, wallet_address=signer_wallet)
    except AuthError:
        return _deny(resource_arn)
    except Exception:
        return _deny(resource_arn)
